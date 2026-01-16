#include <sys/mman.h>

#include <gtk/gtk.h>
#include <jxl/decode.h>
#include "gqview.h"
#include "exif.h"
#include "format_raw.h"


static size_t page_size = 0;

extern gint exif_tiff_parse(ExifData *exif, unsigned char *tiff, guint size, ExifMarker *list);
extern gint exif_tiff_directory_offset(unsigned char *data, const guint len,
		                guint *offset, ExifByteOrder *bo);

gint exif_jxl_parse(ExifData *const restrict exif, const guint size, uint8_t data[const static size], ExifMarker ExifKnownMarkersList[restrict const], const gint parse_color_profile) {

	if (debug)
		printf("exif_jxl_parse\n");

	// marked jxl file?
	const uint32_t jxl_marker[] = { htobe32(0x0000000C), htobe32(0x4A584C20), htobe32(0x0D0A870A)};
	if (size < sizeof(jxl_marker) || memcmp(data, jxl_marker, sizeof(jxl_marker)) != 0) {
		if (debug)
			printf("Not JpegXL identifier");
		if (size >= sizeof(jxl_marker)) {
			printf(": %x %x %x %x -- %x %x %x %x -- %x %x %x %x\n",
					data[0], data[1], data[2], data[3],
					data[4], data[5], data[6], data[7],
					data[8], data[9], data[10], data[11]);
		}
		else {
			printf("\n");
		}
		return -2;
	}

	JxlDecoder *const decoder = JxlDecoderCreate(NULL);
	if (decoder == nullptr)
		return -2;

	if (JXL_DEC_SUCCESS != JxlDecoderSubscribeEvents(decoder, JXL_DEC_BOX | JXL_DEC_BOX_COMPLETE)) {
		if (debug) {
			fprintf(stderr, "JxlDecoderSubscribeEvents failed\n");
		}
		JxlDecoderDestroy(decoder);
		return -1;
	}
	const bool support_decompression = (JXL_DEC_SUCCESS == JxlDecoderSetDecompressBoxes(decoder, JXL_TRUE));
	if (!support_decompression)
		fprintf(stderr, "NOTE: decompressing brob boxes not supported with the currently used jxl library.\n");


	JxlDecoderSetInput(decoder, data, size);
	JxlDecoderCloseInput(decoder);
	
	const constexpr size_t kChunkSize = 65536;
	size_t output_pos = 0;
	bool exif_begun = false;

	JxlDecoderStatus status;
	while ((status = JxlDecoderProcessInput(decoder)) != JXL_DEC_BOX_COMPLETE) {
		if (status == JXL_DEC_ERROR) {
			if (debug)
				printf("JXL decode error\n");
			break;
		}
		if (status == JXL_DEC_NEED_MORE_INPUT) {
			if (debug)
				printf("Truncated JXL file\n");
			// use what we've got
			break;
		}

		if (status == JXL_DEC_BOX) {
			// Another content box --
			if (exif_begun) {
				printf("-- but already begun processing exif\n");
				// We've finished parsing the exif.
				break;
			}
			JxlBoxType boxtype;
			const JxlDecoderStatus status = JxlDecoderGetBoxType(decoder, boxtype, TO_JXL_BOOL(support_decompression));
			if (status != JXL_DEC_SUCCESS) {
				printf("Unable to decode JXL box\n");
				break;
			}

			// Yay?
			exif_begun = (memcmp(boxtype, "Exif", 4) == 0);
			//fall through
		}
		if (!exif_begun) {
			bool breakbreak = false;
			switch (status) {
				case JXL_SIG_NOT_ENOUGH_BYTES:
					printf("JXL_SIG_NOT_ENOUGH_BYTES\n");
					breakbreak = true;
					break;
				case JXL_SIG_INVALID:
					printf("JXL_SIG_INVALID\n");
					breakbreak = true;
					break;
				case JXL_SIG_CODESTREAM:
					// This has no container, no exif data.
					printf("JXL_SIG_CODESTREAM\n");
					breakbreak = true;
					break;
				case JXL_SIG_CONTAINER:
					break;
			}

			if (breakbreak)
				break;
			continue;
		} // has exif begun? (if not..)
		

		// We've got box type Exif.
		if (page_size == 0) {
			page_size = getpagesize();
		}

		size_t compexifsize = 0;
		uint8_t *exifbuf;

		JxlDecoderStatus stat = JxlDecoderGetBoxSizeRaw(decoder, &compexifsize);
		if (stat != JXL_DEC_SUCCESS) {
			printf("Unknown non-success %i from JxlDecoderGetBoxSizeRaw\n", stat);
			exif_begun = 0;
			break;
		}
		if (debug)
			printf("Got box size: %li\n", compexifsize);

		// The *un*compressed size is unknown, so allocate 16x that.
		const size_t bufsz = ({
						// Virtual mem reservations don't take up space until they're used.
						size_t tpsz = (16 * compexifsize + page_size - 1) & ~(page_size-1);
						if (tpsz < (128 << 10))
							tpsz = 128 << 10;
						tpsz;
					}) << 10;
		
		exifbuf = mmap(NULL, bufsz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (exifbuf == MAP_FAILED) {
			perror("Failed to mmap jxl exif buffer (%li)\n"); //, bufsz);
			printf("%p, %i, %li\n", bufsz, bufsz & (page_size-1), sysconf(_SC_PAGE_SIZE));
			exif_begun = 0;
			break;
		}
		if (JxlDecoderSetBoxBuffer(decoder, exifbuf, bufsz) != JXL_DEC_SUCCESS) {
			printf("!DEC_SUCCESS set box buffer\n");
			exif_begun = 0;
			break;
		}

		status = JxlDecoderProcessInput(decoder);

		bool breakbreak = false;
		switch(status) {
			case JXL_DEC_SUCCESS:
			case JXL_DEC_BOX_COMPLETE:
				break;
			case JXL_DEC_ERROR:
				if (debug)
					printf("Got exif-box decode error.\n");
				breakbreak = true;
				break;
			case JXL_DEC_NEED_MORE_INPUT:
				if (debug)
					printf("Truncated jxl file. Need more input processing exif.\n");
				breakbreak = true;
				break;
			case JXL_DEC_BOX:
				if (debug)
					printf("JXL_DEC_BOX\n");
				break;
		}
		if (breakbreak)
			break;

		const size_t exifbytes = bufsz - JxlDecoderReleaseBoxBuffer(decoder);
		//printf("Decompressed exif size: %i\n", exifbytes);

		int i =0 ;
		if (false) {
		for (i = 0; i < exifbytes; i+= 16) {
			printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					exifbuf[i], exifbuf[i+1], exifbuf[i+2], exifbuf[i+3], exifbuf[i+4], exifbuf[i+5], exifbuf[i+6],
					exifbuf[i+7], exifbuf[i+8], exifbuf[i+9], exifbuf[i+10], exifbuf[i+11], exifbuf[i+12],
					exifbuf[i+13], exifbuf[i+14], exifbuf[i+15]);
		}
		while (i < exifbytes) {
			printf("%02x", exifbuf[i]);
		}
		guint offsetdir;
		ExifByteOrder bo;
		int dirres = exif_tiff_directory_offset(exifbuf+4, exifbytes-4, &offsetdir, &bo);

		guint32 offset = 0;
		FormatRawExifParseFunc exif_parse_func;
		int exif_type = format_raw_exif_offset(exifbuf+4+offsetdir, exifbytes-4-offsetdir, &offset, &exif_parse_func);
		}

		// "and the first four bytes of the box contents define the actual box type (e.g. xml ) it represents."
		gint res = exif_tiff_parse(exif, exifbuf+4, exifbytes-4, ExifKnownMarkersList);
		munmap(exifbuf, bufsz);

		// Done or not..
		break;
	} // while process input bytes..

	//JxlReleaseInput(decoder);
	JxlDecoderDestroy(decoder);

	if (status == JXL_DEC_BOX_COMPLETE || exif_begun) {
		return 0;
	}

	return -1;
}
