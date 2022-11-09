#define pr_fmt(fmt) "simplefs: " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>

#include "bitmap.h"
#include "simplefs.h"

static void simplefs_fixup_radix_tree_with_blkid(struct address_space *mapping,
                                                 int bno)
{
    // Modeled after migrate_page_move_mapping() in mm/migrate.c
    struct page *blkid;
    void **pslot;

    spin_lock_irq(&mapping->tree_lock);

    pslot = radix_tree_lookup_slot(&mapping->page_tree, page_index(page));
    // XXX probably can't spin here, but not sure of way to block
    while (radix_tree_deref_slot_protected(pslot, &mapping->tree_lock) != page);

    radix_tree_replace_slot(&mapping->page_tree, pslot, blkid);

    spin_unlock(&mapping->tree_lock);
}

/*
 * Map the buffer_head passed in argument with the iblock-th block of the file
 * represented by inode. If the requested block is not allocated and create is
 * true,  allocate a new block on disk and map it.
 */
static int simplefs_file_get_block(struct inode *inode,
                                   sector_t iblock,
                                   struct buffer_head *bh_result,
                                   int create)
{
    struct super_block *sb = inode->i_sb;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct simplefs_file_ei_block *index;
    struct buffer_head *bh_index;
    bool alloc = false;
    int ret = 0, bno;
    uint32_t extent;
    struct shpage* shpage;

    /* If block number exceeds filesize, fail */
    if (iblock >= SIMPLEFS_MAX_BLOCKS_PER_EXTENT * SIMPLEFS_MAX_EXTENTS)
        return -EFBIG;

    /* Read directory block from disk */
    bh_index = sb_bread(sb, ci->ei_block);
    if (!bh_index)
        return -EIO;
    index = (struct simplefs_file_ei_block *) bh_index->b_data;

    extent = simplefs_ext_search(index, iblock);
    if (extent == -1) {
        ret = -EFBIG;
        goto brelse_index;
    }

    /*
     * Check if iblock is already allocated. If not and create is true,
     * allocate it. Else, get the physical block number.
     */
    if (index->extents[extent].ee_start == 0) {
        if (!create)
            return 0;
        bno = get_free_blocks(sbi, 8);
        if (!bno) {
            ret = -ENOSPC;
            goto brelse_index;
        }
        index->extents[extent].ee_start = bno;
        index->extents[extent].ee_len = 8;
        index->extents[extent].ee_block =
            extent ? index->extents[extent - 1].ee_block +
                         index->extents[extent - 1].ee_len
                   : 0;
        alloc = true;
    } else {
        bno = index->extents[extent].ee_start + iblock -
              index->extents[extent].ee_block;
    }

    /* Map the physical block to to the given buffer_head */
    map_bh(bh_result, sb, bno);

    // Insert block that is about to be read into blkmap
    shpage = blkmap_insert(bno, bh_result->b_page, 1);
    // And fix up pointer in the radix tree to be a blkid instead
    simplefs_fixup_radix_tree_with_blkid(inode->mapping, bno);
    shpage_unlock(shpage);


brelse_index:
    brelse(bh_index);

    return ret;
}

/*
 * Called by the page cache to read a page from the physical disk and map it in
 * memory.
 */
static int simplefs_readpage(struct file *file, struct page *page)
{
    return mpage_readpage(page, simplefs_file_get_block);
}

/*
 * Called by the page cache to write a dirty page to the physical disk (when
 * sync is called or when memory is needed).
 */
static int simplefs_writepage(struct page *page, struct writeback_control *wbc)
{
    return block_write_full_page(page, simplefs_file_get_block, wbc);
}

/*
 * Called by the VFS when a write() syscall occurs on file before writing the
 * data in the page cache. This functions checks if the write will be able to
 * complete and allocates the necessary blocks through block_write_begin().
 */
static int simplefs_write_begin(struct file *file,
                                struct address_space *mapping,
                                loff_t pos,
                                unsigned int len,
                                unsigned int flags,
                                struct page **pagep,
                                void **fsdata)
{
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(file->f_inode->i_sb);
    int err;
    uint32_t nr_allocs = 0;

    /* Check if the write can be completed (enough space?) */
    if (pos + len > SIMPLEFS_MAX_FILESIZE)
        return -ENOSPC;
    nr_allocs = max(pos + len, file->f_inode->i_size) / SIMPLEFS_BLOCK_SIZE;
    if (nr_allocs > file->f_inode->i_blocks - 1)
        nr_allocs -= file->f_inode->i_blocks - 1;
    else
        nr_allocs = 0;
    if (nr_allocs > sbi->nr_free_blocks)
        return -ENOSPC;

    /* prepare the write */
    err = block_write_begin(mapping, pos, len, flags, pagep,
                            simplefs_file_get_block);
    /* if this failed, reclaim newly allocated blocks */
    if (err < 0)
        pr_err("newly allocated blocks reclaim not implemented yet\n");
    return err;
}

/*
 * Called by the VFS after writing data from a write() syscall to the page
 * cache. This functions updates inode metadata and truncates the file if
 * necessary.
 */
static int simplefs_write_end(struct file *file,
                              struct address_space *mapping,
                              loff_t pos,
                              unsigned int len,
                              unsigned int copied,
                              struct page *page,
                              void *fsdata)
{
    struct inode *inode = file->f_inode;
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct super_block *sb = inode->i_sb;
    uint32_t nr_blocks_old;

    /* Complete the write() */
    int ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
    if (ret < len) {
        pr_err("wrote less than requested.");
        return ret;
    }

    nr_blocks_old = inode->i_blocks;

    /* Update inode metadata */
    inode->i_blocks = inode->i_size / SIMPLEFS_BLOCK_SIZE + 2;
    inode->i_mtime = inode->i_ctime = current_time(inode);
    mark_inode_dirty(inode);

    /* If file is smaller than before, free unused blocks */
    if (nr_blocks_old > inode->i_blocks) {
        int i;
        struct buffer_head *bh_index;
        struct simplefs_file_ei_block *index;
        uint32_t first_ext;

        /* Free unused blocks from page cache */
        truncate_pagecache(inode, inode->i_size);

        /* Read ei_block to remove unused blocks */
        bh_index = sb_bread(sb, ci->ei_block);
        if (!bh_index) {
            pr_err("failed truncating '%s'. we just lost %llu blocks\n",
                   file->f_path.dentry->d_name.name,
                   nr_blocks_old - inode->i_blocks);
            goto end;
        }
        index = (struct simplefs_file_ei_block *) bh_index->b_data;

        first_ext = simplefs_ext_search(index, inode->i_blocks - 1);
        /* Reserve unused block in last extent */
        if (inode->i_blocks - 1 != index->extents[first_ext].ee_block)
            first_ext++;

        for (i = first_ext; i < SIMPLEFS_MAX_EXTENTS; i++) {
            if (!index->extents[i].ee_start)
                break;
            put_blocks(SIMPLEFS_SB(sb), index->extents[i].ee_start,
                       index->extents[i].ee_len);
            memset(&index->extents[i], 0, sizeof(struct simplefs_extent));
        }
        mark_buffer_dirty(bh_index);
        brelse(bh_index);
    }
end:
    return ret;
}

struct shpage {
    atomic_t mode;
    int bno;
    struct page *page;
    // XXX -- acquired when shpage is constructed, released once added to blkmap and radix tree
	spinlock_t lock;
    struct h_list_node node;
};

DECLARE_HASHTABLE(blkmap, 16);

static init_blkmap(void) {
    hash_init(blkmap);
}

static struct shpage *blkmap_insert(int bno, struct page *page, int lock) {
    struct shpage *shpage;

    shpage = kzalloc(sizeof(struct shpage), GFP_KERNEL);
    BUG_ON(!shpage);

    shpage->bno = bno;
    shpage->page = page;
    spinlock_init(&shpage->lock);
    if (lock)
        spin_lock(&shpage->irqlock);

    hash_add(blkmap, shpage, key);
}

static void shpage_unlock(struct shpage *shpage) {
    spin_unlock(shpage->lock);
}

static struct shpage *blkmap_find(int bno) {
    struct shpage *shpage;
    hash_for_each_possible(blkmap, shpage, node, bno) {
        if (shpage->bno == bno)
            return shpage;
    }
}

// Called on find_get_entry (page cache hit)
struct page *simplefs_translate_page_ptr(struct page *blkid) {
    struct shpage *shpage;
    int bno;

    bno = (int)(uintptr_t)blkid;
    shpage = blkmap_find(bno);
    // Two cases here.
    if (shpage) {
        // Case 1: blkid is in blkmap: indicates already mapped in local CN
        return shpage->page;
    } else {
        // Case 2: no page has been allocated on this CN yet;
        // get a page and fill it from coherent shared memory.

        // Looks like __page_cache_alloc *is* exported from pagemap.c
        // despite its name.
        page = __page_cache_alloc(GFP_KERNEL);
        BUG_ON(!page);

        blkmap_insert(bno, page, 0);
        // No need to fix up radix tree here. We *got* here because
        // we found a blkid inside the radix tree.
    }
}

const struct address_space_operations simplefs_aops = {
    .readpage = simplefs_readpage,
    .writepage = simplefs_writepage,
    .write_begin = simplefs_write_begin,
    .write_end = simplefs_write_end,
    .translate_page_ptr = simplefs_translate_page_ptr,
};

const struct file_operations simplefs_file_ops = {
    .llseek = generic_file_llseek,
    .owner = THIS_MODULE,
    .read_iter = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
    .fsync = generic_file_fsync,
};
