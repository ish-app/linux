/* IVD - iSH Virtual Disk */
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/blkdev.h>
#include <user/fs.h>

struct ivd {
	int fd;
	const char *file;
	spinlock_t lock;
	struct request_queue *queue;
	struct gendisk *disk;
};
static struct ivd ivd0;

static char ivd_file[1024];
module_param_string(file0, ivd_file, sizeof(ivd_file), 0444);

static void ivd_submit_bio(struct bio *bio)
{
	struct ivd *ivd = bio->bi_bdev->bd_disk->private_data;
	struct bio_vec bvec;
	struct bvec_iter iter;
	size_t offset = bio->bi_iter.bi_sector << SECTOR_SHIFT;
	bio_for_each_segment(bvec, bio, iter) {
		void *data = page_to_virt(bvec.bv_page) + bvec.bv_offset;
		unsigned size = bvec.bv_len;
		int err = 0;
		switch (bio_op(bio)) {
		case REQ_OP_READ:
			err = host_pread(ivd->fd, data, size, offset);
			break;
		case REQ_OP_WRITE:
			err = host_pwrite(ivd->fd, data, size, offset);
			break;
		default:
			bio->bi_status = BLK_STS_NOTSUPP;
			break;
		}
		if (err < 0)
			bio->bi_status = errno_to_blk_status(err);
		offset += size;
	}
	bio_endio(bio);
}

static struct block_device_operations ivd_fops = {
	.submit_bio = ivd_submit_bio,
};

static int ivd_major;
static int __init ivd_init(void)
{
	struct ivd *ivd;
	int err;

	ivd_major = register_blkdev(0, "ivd");
	if (ivd_major < 0)
		return ivd_major;

	if (*ivd_file) {
		ssize_t ivd_size;

		printk("ivd: %s\n", ivd_file);
		ivd = &ivd0;
		ivd->fd = host_open(ivd_file, O_RDWR);
		ivd->disk = blk_alloc_disk(NUMA_NO_NODE);
		if (!ivd->disk)
			return -ENOMEM;
		ivd->disk->major = ivd_major;
		ivd->disk->first_minor = 0; // there is only one, for now, I guess?
		ivd->disk->minors = 1;
		ivd->disk->fops = &ivd_fops;
		strcpy(ivd->disk->disk_name, "ivd0");
		ivd->disk->private_data = &ivd0;
		err = host_fstat_size(ivd->fd, &ivd_size);
		if (err < 0) {
			printk("ivd: %s: failed to get size\n", ivd_file);
			return err;
		}
		set_capacity(ivd->disk, ivd_size / SECTOR_SIZE);
		err = add_disk(ivd->disk);
		if (err) {
			blk_cleanup_disk(ivd->disk);
			return err;
		}
	}
	
	return 0;
}
late_initcall(ivd_init);
