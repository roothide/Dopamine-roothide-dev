
#include <choma/FAT.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MachOByteOrder.h>
#include <choma/CodeDirectory.h>
#include <sys/param.h>
#include "log.h"

extern CS_DecodedBlob *csd_superblob_find_best_code_directory(CS_DecodedSuperBlob *decodedSuperblob);
extern bool csd_code_directory_calculate_page_hash(CS_DecodedBlob *codeDirBlob, MachO *macho, int slot, uint8_t *pageHashOut);

MachO *ljb_fat_find_preferred_slice(FAT *fat)
{
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }
	
	MachO *candidateSlice = NULL;

	if (cpusubtype == CPU_SUBTYPE_ARM64E) {
		// New arm64e ABI
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
		if (!candidateSlice) {
			// Old arm64e ABI
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
			if (candidateSlice) {
				// If we found an old arm64e slice, make sure this is a library! If it's a binary, skip!!!
				// For binaries the system will fall back to the arm64 slice, which has the CDHash that we want to add
				if (macho_get_filetype(candidateSlice) == MH_EXECUTE) candidateSlice = NULL;
			}
		}
	}

	if (!candidateSlice) {
		// On iOS 15+ the kernels prefers ARM64_V8 to ARM64_ALL
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
		if (!candidateSlice) {
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
		}
	}

	return candidateSlice;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
	CS_DecodedBlob *wrapperBlob = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
	if (wrapperBlob) {
		if (csd_blob_get_size(wrapperBlob) > 8) {
			return false;
		}
	}
	return true;
}

FAT *fat_init_for_writing(const char *filePath)
{
    MemoryStream *stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE);
    if (stream) {
        return fat_init_from_memory_stream(stream);;
    }
    return NULL;
}

int calc_cdhash(uint8_t *cdBlob, size_t cdBlobSize, uint8_t hashtype, void *cdhashOut)
{
    // Longest possible buffer, will cut it off at the end as cdhash size is fixed
    uint8_t cdhash[CC_SHA384_DIGEST_LENGTH];

    JBLogDebug("head=%llx  %lx\n", *(uint64_t*)cdBlob, cdBlobSize);

    switch (hashtype) {
		case CS_HASHTYPE_SHA160_160: {
			CC_SHA1(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}
		
		case CS_HASHTYPE_SHA256_256:
		case CS_HASHTYPE_SHA256_160: {
			CC_SHA256(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

		case CS_HASHTYPE_SHA384_384: {
			CC_SHA384(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

        default:
        return -1;
	}

    memcpy(cdhashOut, cdhash, CS_CDHASH_LEN);
    return 0;
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

bool is_app_path(const char* path)
{
    if(!path) return false;

    char rp[PATH_MAX];
    if(!realpath(path, rp)) return false;

    if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return false;

    char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return false;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return false;

	return true;
}

int ensure_randomized_cdhash(const char* inputPath, void* cdhashOut)
{
	if(access(inputPath, W_OK) != 0)
		return -1;
		
	// Initialise the FAT structure
    JBLogDebug("Initialising FAT structure from %s.\n", inputPath);
    FAT *fat = fat_init_for_writing(inputPath);
    if (!fat) return -1;

    MachO *macho = ljb_fat_find_preferred_slice(fat);
	if(!macho) {
		fat_free(fat);
		return -1;
	}
    JBLogDebug("preferred slice: %llx\n", macho->archDescriptor.offset);

	__block int foundCount = 0;
    __block uint64_t textsegoffset = 0;
    __block uint64_t firstsectoffset = 0;
	__block struct section_64 firstsection={0};
    __block struct segment_command_64 textsegment={0};
    __block struct linkedit_data_command linkedit={0};

    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		bool foundOne = false;
		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segmentCommand = ((struct segment_command_64 *)cmd);

			if (strcmp(segmentCommand->segname, "__TEXT") != 0) return;

			textsegoffset = offset;
			textsegment = *segmentCommand;

			if(segmentCommand->nsects==0) {
				*stop=true;
				return;
			}

			firstsectoffset = textsegoffset + sizeof(*segmentCommand);
			firstsection = *(struct section_64*)((uint64_t)segmentCommand + sizeof(*segmentCommand));
			if (strcmp(firstsection.segname, "__TEXT") != 0) {
				*stop=true;
				return;
			}
			
			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
			JBLogDebug("LC_CODE_SIGNATURE: %x\n", csLoadCommand->dataoff);

			linkedit = *csLoadCommand;

			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
    });

    if(foundCount < 2) {
		fat_free(fat);
		return -1;
	}

    uint64_t* rd = (uint64_t*)&(textsegment.segname[sizeof(textsegment.segname)-sizeof(uint64_t)]);
    uint64_t* rd2 = (uint64_t*)&(firstsection.segname[sizeof(firstsection.segname)-sizeof(uint64_t)]);
    JBLogDebug("__TEXT: %llx,%llx, %016llX %016llX\n", textsegoffset, textsegment.fileoff, *rd, *rd2);

	bool isAppPath = is_app_path(inputPath);
	
	//Ignore removable system apps
	if(isAppPath && rd==0 && rd2==0) {
		fat_free(fat);
        return -1;
	}

    int retval=-1;

    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        JBLogDebug("Error: no code signature found, please fake-sign the binary at minimum before running the bypass.\n");
		fat_free(fat);
        return -1;
    }

    JBLogDebug("super blob: %x %x %d\n", superblob->magic, BIG_TO_HOST(superblob->length), BIG_TO_HOST(superblob->count));

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if(!decodedSuperblob) {
		free(superblob);
		fat_free(fat);
		return -1;
	}

	do
	{
		CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
		if(!bestCDBlob) break;
		
		uint64_t jbrand = strtoull(getenv("JBRAND"),NULL,16);

		if(!isAppPath && *rd==0 && *rd2 == jbrand) 
		{
			retval = csd_code_directory_calculate_hash(bestCDBlob, cdhashOut);
			break;
		}

		if(*rd != 0) //fix it patched on v1.0.8
		{
			*rd = 0;
			if(memory_stream_write(fat->stream, macho->archDescriptor.offset + textsegoffset, sizeof(textsegment), &textsegment) != 0) {
				break;
			}
		}

		if(isAppPath) {
			*rd2 = 0; //fix removable system apps patched on previous version
		} else {
			*rd2 = jbrand;
		}
		if(memory_stream_write(fat->stream, macho->archDescriptor.offset + firstsectoffset, sizeof(firstsection), &firstsection) != 0) {
			break;
		}
				
		CS_CodeDirectory codeDir;
		if(csd_blob_read(bestCDBlob, 0, sizeof(CS_CodeDirectory), &codeDir) != 0) {
			break;
		}

		CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDir, BIG_TO_HOST_APPLIER);

		uint8_t pageHash[codeDir.hashSize];
		if(!csd_code_directory_calculate_page_hash(bestCDBlob, macho, 0, pageHash)) {
			break;
		}

		for (uint32_t i = 0; i < BIG_TO_HOST(superblob->count); i++) {
			CS_BlobIndex curIndex = superblob->index[i];
			BLOB_INDEX_APPLY_BYTE_ORDER(&curIndex, BIG_TO_HOST_APPLIER);
			//JBLogDebug("decoding %u (type: %x, offset: 0x%x)\n", i, curIndex.type, curIndex.offset);

			if(curIndex.type == bestCDBlob->type)
			{
				if(0 != memory_stream_write(fat->stream, macho->archDescriptor.offset + linkedit.dataoff + curIndex.offset + codeDir.hashOffset, codeDir.hashSize, pageHash)) {
					break;
				}

				void* newCDBlob = malloc(codeDir.length);

				if(memory_stream_read(fat->stream, macho->archDescriptor.offset + linkedit.dataoff + curIndex.offset, codeDir.length, newCDBlob) == 0) {

					retval = calc_cdhash(newCDBlob, codeDir.length, csd_code_directory_get_hash_type(bestCDBlob), cdhashOut);
				
				}

				free(newCDBlob);

				break;
			}
		}

	} while(0);

	csd_superblob_free(decodedSuperblob);
	free(superblob);
	fat_free(fat);

	return retval;
}
