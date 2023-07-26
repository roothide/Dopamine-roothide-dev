#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/event.h>
#include <sys/syscall.h>

#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>

#include "vnode.h"

#define LOG JBLogDebug
extern uint64_t xpaci(uint64_t);

struct  namecache {
	TAILQ_ENTRY(namecache)  nc_entry;       /* chain of all entries */
	TAILQ_ENTRY(namecache)  nc_child;       /* chain of ncp's that are children of a vp */
	union {
		LIST_ENTRY(namecache)  nc_link; /* chain of ncp's that 'name' a vp */
		TAILQ_ENTRY(namecache) nc_negentry; /* chain of ncp's that 'name' a vp */
	} nc_un;
	LIST_ENTRY(namecache)   nc_hash;        /* hash chain */
	vnode_t                 nc_dvp;         /* vnode of parent of name */
	vnode_t                 nc_vp;          /* vnode the name refers to */
	unsigned int            nc_hashval;     /* hashval of stringname */
	const char              *nc_name;       /* pointer to segment name in string cache */
};

static unsigned int crc32tab[256];

static void
init_crc32(void)
{
	/*
	 * the CRC-32 generator polynomial is:
	 *   x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^10
	 *        + x^8  + x^7  + x^5  + x^4  + x^2  + x + 1
	 */
	unsigned int crc32_polynomial = 0x04c11db7;
	unsigned int i, j;

	/*
	 * pre-calculate the CRC-32 remainder for each possible octet encoding
	 */
	for (i = 0; i < 256; i++) {
		unsigned int crc_rem = i << 24;

		for (j = 0; j < 8; j++) {
			if (crc_rem & 0x80000000) {
				crc_rem = (crc_rem << 1) ^ crc32_polynomial;
			} else {
				crc_rem = (crc_rem << 1);
			}
		}
		crc32tab[i] = crc_rem;
	}
}

unsigned int
hash_string(const char *cp, int len)
{
	unsigned hash = 0;

	if (len) {
		while (len--) {
			hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
		}
	} else {
		while (*cp != '\0') {
			hash = crc32tab[((hash >> 24) ^ (unsigned char)*cp++)] ^ hash << 8;
		}
	}
	/*
	 * the crc generator can legitimately generate
	 * a 0... however, 0 for us means that we
	 * haven't computed a hash, so use 1 instead
	 */
	if (hash == 0) {
		hash = 1;
	}
	return hash;
}

static void print_nc(uint64_t ncp) 
{
	while(ncp) {

		struct namecache nc={0};
		kreadbuf(ncp, &nc, sizeof(nc));

		char namebuf[128]={0};
		for(int i=0; i<sizeof(namebuf)/sizeof(namebuf[0]); i++)
			if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

		LOG("nc %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name, 
				nc.nc_hash.le_next, nc.nc_hash.le_prev, nc.nc_hash.le_prev?kread64((uint64_t) nc.nc_hash.le_prev):0, namebuf);

		ncp = (uint64_t)nc.nc_hash.le_next;
	}
}

#include <libgen.h>
 int unsandbox(char* dir, char* file)
{
	int ret = 0;
	int filefd=-1,dirfd=-1;

	 dirfd = open(dir, O_RDONLY);
	if(dirfd<0) {
		JBLogError("open dir failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	 filefd = open(file, O_RDONLY);
	if(filefd<0) {
		JBLogError("open file failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	uint64_t dirvp = proc_get_vnode_by_file_descriptor(self_proc(), dirfd);
	if(!dirvp) {
		JBLogError("get dirvp failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	struct vnode dirvnode;
	kreadbuf(dirvp, &dirvnode, sizeof(dirvnode));
	kwrite32(dirvp+offsetof(struct vnode, v_usecount), dirvnode.v_usecount+1);

	uint64_t filevp = proc_get_vnode_by_file_descriptor(self_proc(), filefd);
	if(!filevp) {
		JBLogError("get filevp failed %d,%s", errno, strerror(errno));
		goto failed;
	}

	struct vnode filevnode;
	kreadbuf(filevp, &filevnode, sizeof(filevnode));

	kwrite32(filevp+offsetof(struct vnode, v_usecount), filevnode.v_usecount+1);


	struct vnode parentvnode;
	uint64_t parentvp = xpaci((uint64_t)filevnode.v_parent);
	kreadbuf(parentvp, &parentvnode, sizeof(parentvnode));
	kwrite32(parentvp+offsetof(struct vnode, v_usecount), parentvnode.v_usecount+1);


	JBLogDebug("filefd=%d filevp=%llx fileid=%lld parent=%llx dirvp=%llx dirid=%lld\n", filefd, filevp, filevnode.v_id, filevnode.v_parent, dirvp, dirvnode.v_id);

	struct namecache filenc={0};
	uint64_t filencp = (uint64_t)filevnode.v_nclinks.lh_first;
	kreadbuf(filencp, &filenc, sizeof(filenc));
	JBLogDebug("filefd=%d filevp=%llx fileid=%lld parent=%llx dirvp=%llx dirid=%lld ncchildren=%llx:%llx->%llx\n", 
		filefd, filevp, filevnode.v_id, filevnode.v_parent, dirvp, dirvnode.v_id, dirvnode.v_ncchildren.tqh_first, dirvnode.v_ncchildren.tqh_last, 
		dirvnode.v_ncchildren.tqh_last?kread64((uint64_t)dirvnode.v_ncchildren.tqh_last):0);

{
	uint64_t ncp=(uint64_t)dirvnode.v_ncchildren.tqh_first;
	while(ncp) {

		struct namecache nc={0};
		kreadbuf(ncp, &nc, sizeof(nc));

		char namebuf[128]={0};
		for(int i=0; i<sizeof(namebuf)/sizeof(namebuf[0]); i++)
			if( !(namebuf[i]=kread8((uint64_t)nc.nc_name+i)) ) break;

		LOG("child %llx hashval=%08x vp=%16llx dvp=%llx name=%llx next=%16llx prev=%llx,%llx %s\n", ncp, nc.nc_hashval, nc.nc_vp, nc.nc_dvp, nc.nc_name, 
				nc.nc_child.tqe_next, nc.nc_child.tqe_prev, nc.nc_child.tqe_prev?kread64((uint64_t) nc.nc_child.tqe_prev):0, namebuf);

		ncp = (uint64_t)nc.nc_child.tqe_next;
	}
}

	init_crc32();
	uint32_t hash_val = hash_string(basename(file), 0);
	JBLogDebug("hash=%x\n", hash_val);

	uint64_t kernelslide = bootInfo_getUInt64(@"kernelslide");
	JBLogDebug("kernelslide=%llx\n", kernelslide);
	uint64_t nchashtbl = kread64(kernelslide+ bootInfo_getUInt64(@"nchashtbl"));
	uint64_t nchashmask = kread64(kernelslide+ bootInfo_getUInt64(@"nchashmask"));
	JBLogDebug("nchashtbl=%llx nchashmask=%llx\n", nchashtbl, nchashmask);
	// for(int i=0; i<nchashmask; i++) {
	// 	JBLogDebug("hash[%d]=%llx\n", i, kread64(nchashtbl+i*8));
	// }

	uint32_t index = (dirvnode.v_id ^ (hash_val)) & nchashmask; //*********dirv2?
	uint64_t ncpp = nchashtbl + index*8;
	uint64_t ncp = kread64(ncpp);
	JBLogDebug("index=%x ncpp=%llx ncp=%llx\n", index, ncpp, ncp);

	JBLogDebug("dir hash chain\n");
	print_nc(kread64(ncpp));
	

	//return 0; //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	kwrite64(filencp+offsetof(struct namecache,nc_dvp), dirvp);
	kwrite_ptr(filevp+offsetof(struct vnode, v_parent), (uint64_t)dirvp, 0xF506);

/*

#define LIST_CHECK_HEAD(head, field) do {                               \
	if (__improbable(                                               \
	      LIST_FIRST((head)) != NULL &&                             \
	      LIST_FIRST((head))->field.le_prev !=                      \
	      &LIST_FIRST((head))))                                     \
	             panic("Bad list head %p first->prev != head @%u",  \
	                 (head), __LINE__);                             \
} while (0)

#define LIST_CHECK_NEXT(elm, field) do {                                \
	if (__improbable(                                               \
	      LIST_NEXT((elm), field) != NULL &&                        \
	      LIST_NEXT((elm), field)->field.le_prev !=                 \
	      &((elm)->field.le_next)))                                 \
	             panic("Bad link elm %p next->prev != elm @%u",     \
	                 (elm), __LINE__);                              \
} while (0)

#define LIST_CHECK_PREV(elm, field) do {                                \
	if (__improbable(*(elm)->field.le_prev != (elm)))               \
	        panic("Bad link elm %p prev->next != elm @%u",          \
	            (elm), __LINE__);                                   \
} while (0)


#define LIST_INSERT_HEAD(head, elm, field) do {                         \
	LIST_CHECK_HEAD((head), field);                         \
	if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)     \
	        LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
	LIST_FIRST((head)) = (elm);                                     \
	(elm)->field.le_prev = &LIST_FIRST((head));                     \
} while (0)

#define LIST_NEXT(elm, field)   ((elm)->field.le_next)

#define LIST_REMOVE(elm, field) do {                                    \
	LIST_CHECK_NEXT(elm, field);                            \
	LIST_CHECK_PREV(elm, field);                            \
	if (LIST_NEXT((elm), field) != NULL)                            \
	        LIST_NEXT((elm), field)->field.le_prev =                \
	            (elm)->field.le_prev;                               \
	*(elm)->field.le_prev = LIST_NEXT((elm), field);                \
	TRASHIT((elm)->field.le_next);                                  \
	TRASHIT((elm)->field.le_prev);                                  \
} while (0)

分析:
内核最频繁的操作是namei->LIST_FOREACH, 这个没有任何检查, 只要不崩溃就行.
然后就是删除和插入了:
删除是LIST_REMOVE, 会在任意一个nc上直接进行, 不会进行遍历, 会同时进行LIST_CHECK_NEXT和LIST_CHECK_PREV检查
插入的话只发现了LIST_INSERT_HEAD, 只有LIST_CHECK_HEAD检查

然后就是断链和重新插入两个步骤

断链的话我们自己的nc本身应该是不会被删除的, 但是内核随时可能会从我们前面插入(head), 或者删除我们前后的nc


	TAILQ_REMOVE(&(ncp->nc_dvp->v_ncchildren), ncp, nc_child);


	今天发现有时候会突然莫名其妙在nchashtbl前面插入一个vp=0的同样的nc导致访问不到, 一会这个nc又消失了
	发生的还挺频繁的.....

long    numcache;//当前已经存在的nc数量
int     desiredNodes;//允许存在最大nc数量, 超过就会复用/删除最早的TAILQ_REMOVE(&nchead, ncp, nc_entry); cache_delete(TAILQ_FIRST(&nchead), 0)
int     desiredNegNodes;//允许存在的最大无效nc数量, 超过就会删除最早的cache_delete(TAILQ_FIRST(&neghead), 1)
int     ncs_negtotal;//当前已经存在的无效nc数量

(no xnu call, my fs will call?)->cache_enter->cache_enter_locked
lookup_consider_update_cache->cache_enter_with_gen->cache_enter_locked 不可能是从这里过来的, 这里调用前都有判断vp!=null
vnode_create_internal->cache_enter_create->cache_enter_locked  这里过来vp!=null


分析:
内核最频繁的操作是namei->LIST_FOREACH, 这个没有任何检查, 只要不崩溃就行.
然后就是删除和插入了:
删除是LIST_REMOVE, 会在任意一个nc上直接进行, 不会进行遍历, 会同时进行LIST_CHECK_NEXT和LIST_CHECK_PREV检查
插入的话只发现了LIST_INSERT_HEAD, 只有LIST_CHECK_HEAD检查

然后就是断链和重新插入两个步骤

断链的话我们自己的nc本身应该是不会被删除的, 但是内核随时可能会从我们前面插入(head), 或者删除我们前后的nc

vfs_cache:2516 (LIST_CHECK_PREV:0xfffffffe0f7021860)
	LIST_REMOVE(ncp, nc_hash);


出现一个panic
  "panicString" : "panic(cpu 3 caller 0xfffffff00eec01ac): [namecache]: element modified after free (off:16, val:0xffffffe0f7e83420, sz:96, ptr:0xffffffe0f6fa1680)
   16: 0xffffffe0f7e83420

   cache_enter_locked在使用zalloc分配nc的时候, 发现这个buf之前被释放后又被写入了数据, 这个buf是之前的filenc, 
   偏移量16(0x10)刚好是nc_child->tqe_next(地址0xffffffe0f7e83420), 写入的值也是0xffffffe0f7e83420

猜测可能是clean invalid引起的.
今天再次出现了这个情况, 发现ptr就是我们的filencp

又遇到了这个情况, jbctl updaat的时候, 在launchd重新exec前, 但是前面userspace reboot一直没事, 感觉可能是删除文件导致的.


*/


	//LIST_REMOVE(ncp, nc_hash):
	{
		uint64_t ncp = filencp;
		
		if(filenc.nc_hash.le_next) {
			//LIST_NEXT((elm), field)->field.le_prev =(elm)->field.le_prev;
			kwrite64((uint64_t)filenc.nc_hash.le_next+offsetof(struct namecache, nc_hash.le_prev), (uint64_t)filenc.nc_hash.le_prev); //next->prev = prev
		}

		//*(elm)->field.le_prev = LIST_NEXT((elm), field);
		kwrite64((uint64_t)filenc.nc_hash.le_prev, (uint64_t)filenc.nc_hash.le_next);
	}
	//LIST_INSERT_HEAD(ncpp, ncp, nc_hash):
	{
		uint64_t ncp = filencp;

		uint64_t first = kread64(ncpp);
		kwrite64(ncp+offsetof(struct namecache, nc_hash.le_next), first);
		if(first) { //if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)
			//LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);
			kwrite64(first+offsetof(struct namecache, nc_hash.le_prev),  ncp+offsetof(struct namecache, nc_hash.le_next) );
		}
		kwrite64(ncpp, ncp); //LIST_FIRST((head)) = (elm);
		kwrite64(ncp+offsetof(struct namecache, nc_hash.le_prev), ncpp); //(elm)->field.le_prev = &LIST_FIRST((head));
	}

	//TAILQ_REMOVE(&(ncp->nc_dvp->v_ncchildren), ncp, nc_child);
	{	
		uint64_t ncp = filencp;
		if(filenc.nc_child.tqe_next) { //always true for filenc next time
			//TAILQ_NEXT((elm), field)->field.tqe_prev = (elm)->field.tqe_prev;
			kwrite64((uint64_t)filenc.nc_child.tqe_next+offsetof(struct namecache, nc_child.tqe_prev), (uint64_t)filenc.nc_child.tqe_prev);
		} else {
			//(head)->tqh_last = (elm)->field.tqe_prev;
			kwrite64(parentvp+offsetof(struct vnode,v_ncchildren.tqh_last), (uint64_t)filenc.nc_child.tqe_prev);
		}
		//*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);
		kwrite64((uint64_t)filenc.nc_child.tqe_prev, (uint64_t)filenc.nc_child.tqe_next);

		kwrite64(filencp+offsetof(struct namecache,nc_child.tqe_next), filencp); //TAILQ_CHECK_NEXT
		kwrite64(filencp+offsetof(struct namecache,nc_child.tqe_prev), filencp+offsetof(struct namecache,nc_child.tqe_next)); //TAILQ_CHECK_PREV
	}

	JBLogDebug("final hash chain\n");
	print_nc(kread64(ncpp));


	JBLogDebug("unsandboxed %llx %llx %s %s\n\n", filevp, dirvp, file, dir);

	ret = 0;
	goto success;

failed:
	ret = -1;

success:
	if(dirfd>=0) close(dirfd);
	if(filefd>=0) close(filefd);

	return ret;
}
