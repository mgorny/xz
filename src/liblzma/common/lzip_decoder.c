///////////////////////////////////////////////////////////////////////////////
//
/// \file       lzip_decoder.c
/// \brief      Decodes .lz Streams
//
//  Author:     Michał Górny
//              Lasse Collin
//
//  This file has been put into the public domain.
//  You can do whatever you want with this file.
//
///////////////////////////////////////////////////////////////////////////////

#include "lzip_decoder.h"
#include "lzma_decoder.h"


#define LZIP_MEMBER_HEADER_SIZE 2
#define LZIP_MEMBER_FOOTER_SIZE 20


typedef struct {
	enum {
		SEQ_MEMBER_MAGIC,
		SEQ_MEMBER_HEADER,
		SEQ_CODER_INIT,
		SEQ_LZMA_STREAM,
		SEQ_MEMBER_FOOTER,
		SEQ_TRAILING_JUNK,
	} sequence;

	lzma_next_coder lzma_decoder;

	/// Position in the header fields
	size_t pos;

	/// Memory usage limit
	uint64_t memlimit;

	/// Amount of memory actually needed (only an estimate)
	uint64_t memusage;

	/// If true, LZMA_GET_CHECK is returned after decoding Stream Header.
	bool tell_any_check;

	/// If true, we will tell the Block decoder to skip calculating
	/// and verifying the integrity check.
	bool ignore_check;

	/// If true, we will decode concatenated Streams that possibly have
	/// Stream Padding between or after them. LZMA_STREAM_END is returned
	/// once the application isn't giving us any new input, and we aren't
	/// in the middle of a Stream, and possible Stream Padding is a
	/// multiple of four bytes.
	bool concatenated;

	/// When decoding concatenated Streams, this is true as long as we
	/// are decoding the first Stream. This is needed to avoid misleading
	/// LZMA_FORMAT_ERROR in case the later Streams don't have valid magic
	/// bytes.
	bool first_stream;

	/// Buffer to hold Stream Header, Block Header, and Stream Footer.
	/// Block Header has biggest maximum size.
	uint8_t buffer[LZIP_MEMBER_FOOTER_SIZE];

	/// Options decoded from the header needed to initialize
	/// the LZMA decoder
	lzma_options_lzma options;

	uint64_t member_size;
	uint64_t uncompressed_size;
} lzma_lzip_coder;


static lzma_ret
lzip_decoder_reset(lzma_lzip_coder *coder, const lzma_allocator *allocator)
{
	// Reset the rest of the variables.
	coder->sequence = SEQ_MEMBER_MAGIC;
	coder->pos = 0;

	return LZMA_OK;
}


const uint8_t lzip_header_magic[4] = {0x4C, 0x5A, 0x49, 0x50};


static lzma_ret
lzip_member_header_decode(lzma_options_lzma *options, const uint8_t *in)
{
	// Version (1 at the moment)
	if (in[0] != 1)
		return LZMA_FORMAT_ERROR;

	// Coded Dictionary Size
	// bits 7..5 -> fracnum (fraction numerator), 0..7
	// bits 4..0 -> b2log (base 2 log of base size), 12..29
	const uint8_t ds = in[1];
	const uint8_t b2log = ds & 0x1F;
	const uint8_t fracnum = (ds & 0xE0) >> 5;

	if (b2log < 12 || b2log > 29)
		return LZMA_FORMAT_ERROR;

	//   2^[b2log] - ([fracnum] / 16) * 2^[b2log]
	// = 2^[b2log] - [fracnum] * 2^([b2log] - 4)
	options->dict_size = (1 << b2log) - fracnum * (1 << (b2log - 4));
	options->preset_dict = NULL;
	options->lc = 3;
	options->lp = 0;
	options->pb = 2;

	return LZMA_OK;
}


typedef struct {
	uint32_t crc32;
	uint64_t uncompressed_size;
	uint64_t member_size;
} lzip_footer_flags;


static lzma_ret
lzip_member_footer_decode(lzip_footer_flags *flags, const uint8_t *in)
{
	flags->crc32 = read32le(in);
	flags->uncompressed_size = read64le(&in[4]);
	flags->member_size = read64le(&in[12]);

	return LZMA_OK;
}


static lzma_ret
lzip_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size, lzma_action action)
{
	lzma_lzip_coder *coder = coder_ptr;

	// When decoding the actual Block, it may be able to produce more
	// output even if we don't give it any new input.
	while (true)
	switch (coder->sequence) {
	case SEQ_MEMBER_MAGIC: {
		// Copy the Magic bytes to the internal buffer.
		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				sizeof(lzip_header_magic));

		// Return if we didn't get all Magic bytes yet.
		if (coder->pos < sizeof(lzip_header_magic)) {
			// If we are on 2nd+ concatenated stream, and it ends before
			// one more magic could fit, we discard the junk and finish.
			if (!coder->first_stream && action == LZMA_FINISH)
				return LZMA_STREAM_END;
			else
				return LZMA_OK;
		}

		coder->pos = 0;
		coder->member_size = sizeof(lzip_header_magic);
		coder->uncompressed_size = 0;

		// Verify them.
		if (memcmp(coder->buffer, lzip_header_magic,
					sizeof(lzip_header_magic)) != 0) {
			// If we are past the first stream of a concatenated file
			// and the trailing data does not look like another stream,
			// lzip tells us to discard it all.
			if (!coder->first_stream) {
				coder->sequence = SEQ_TRAILING_JUNK;
				break;
			} else
				return LZMA_FORMAT_ERROR;
		}

		coder->sequence = SEQ_MEMBER_HEADER;
    }

	// Fall through

	case SEQ_MEMBER_HEADER: {
		// Copy the Member Header to the internal buffer.
		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				LZIP_MEMBER_HEADER_SIZE);

		// Return if we didn't get the whole Member Header yet.
		if (coder->pos < LZIP_MEMBER_HEADER_SIZE)
			return LZMA_OK;

		coder->pos = 0;
		coder->member_size += LZIP_MEMBER_HEADER_SIZE;

		// Decode the Member Header.
		lzma_ret ret = lzip_member_header_decode(&coder->options,
				coder->buffer);
		if (ret != LZMA_OK)
			return ret == LZMA_FORMAT_ERROR && !coder->first_stream
					? LZMA_DATA_ERROR : ret;

		coder->first_stream = false;

		// Calculate the memory usage limit.
		coder->memusage = lzma_lzma_decoder_memusage(&coder->options)
				+ LZMA_MEMUSAGE_BASE;

		coder->sequence = SEQ_CODER_INIT;

		if (coder->tell_any_check)
			return LZMA_GET_CHECK;
	}

	// Fall through

	case SEQ_CODER_INIT: {
		if (coder->memusage > coder->memlimit)
			return LZMA_MEMLIMIT_ERROR;

		lzma_filter_info filters[2] = {
			{
				.init = &lzma_lzma_decoder_init,
				.options = &coder->options,
			}, {
				.init = NULL,
			}
		};

		const lzma_ret ret = lzma_next_filter_init(&coder->lzma_decoder,
				allocator, filters);
		if (ret != LZMA_OK)
			return ret;

		coder->sequence = SEQ_LZMA_STREAM;
	}

	// Fall through

	case SEQ_LZMA_STREAM: {
		const size_t in_pos_before = *in_pos;
		const size_t out_pos_before = *out_pos;

		const lzma_ret ret = coder->lzma_decoder.code(
				coder->lzma_decoder.coder, allocator,
				in, in_pos, in_size, out, out_pos, out_size,
				action);

		// Count the consumed and output data.
		coder->member_size += *in_pos - in_pos_before;
		coder->uncompressed_size += *out_pos - out_pos_before;

		if (ret != LZMA_STREAM_END)
			return ret;

		coder->sequence = SEQ_MEMBER_FOOTER;
		break;
	}

	// Fall through

	case SEQ_MEMBER_FOOTER: {
		// Copy the Member Footer to the internal buffer.
		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				LZIP_MEMBER_FOOTER_SIZE);

		// Return if we didn't get the whole Stream Footer yet.
		if (coder->pos < LZIP_MEMBER_FOOTER_SIZE)
			return LZMA_OK;

		coder->pos = 0;
		coder->member_size += LZIP_MEMBER_FOOTER_SIZE;

		// Decode the Member Footer.
		lzip_footer_flags footer_flags;
		const lzma_ret ret = lzip_member_footer_decode(
				&footer_flags, coder->buffer);
		if (ret != LZMA_OK)
			return ret;

		// Verify the stored sizes.
		if (coder->uncompressed_size != footer_flags.uncompressed_size)
			return LZMA_DATA_ERROR;
		if (coder->member_size != footer_flags.member_size)
			return LZMA_DATA_ERROR;

		// TODO: verify CRC32

		if (!coder->concatenated)
			return LZMA_STREAM_END;

		// Prepare to decode the next Stream.
		return_if_error(lzip_decoder_reset(coder, allocator));

		coder->sequence = SEQ_MEMBER_MAGIC;
		break;
	}

	case SEQ_TRAILING_JUNK: {
		assert(coder->concatenated);

		// Skip over possible Stream Padding.
		*in_pos = in_size;
		if (action == LZMA_FINISH)
			return LZMA_STREAM_END;
		return LZMA_OK;
	}

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}

	// Never reached
}


static void
lzip_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_lzip_coder *coder = coder_ptr;
	lzma_next_end(&coder->lzma_decoder, allocator);
	lzma_free(coder, allocator);
	return;
}


static lzma_ret
lzip_decoder_memconfig(void *coder_ptr, uint64_t *memusage,
		uint64_t *old_memlimit, uint64_t new_memlimit)
{
	lzma_lzip_coder *coder = coder_ptr;

	*memusage = coder->memusage;
	*old_memlimit = coder->memlimit;

	if (new_memlimit != 0) {
		if (new_memlimit < coder->memusage)
			return LZMA_MEMLIMIT_ERROR;

		coder->memlimit = new_memlimit;
	}

	return LZMA_OK;
}


extern lzma_ret
lzma_lzip_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, uint32_t flags)
{
	lzma_next_coder_init(&lzma_lzip_decoder_init, next, allocator);

	if (flags & ~LZMA_SUPPORTED_FLAGS)
		return LZMA_OPTIONS_ERROR;

	lzma_lzip_coder *coder = next->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_lzip_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &lzip_decode;
		next->end = &lzip_decoder_end;
		next->memconfig = &lzip_decoder_memconfig;

		coder->lzma_decoder = LZMA_NEXT_CODER_INIT;
	}

	coder->memlimit = my_max(1, memlimit);
	coder->memusage = LZMA_MEMUSAGE_BASE;
	coder->tell_any_check = (flags & LZMA_TELL_ANY_CHECK) != 0;
	coder->ignore_check = (flags & LZMA_IGNORE_CHECK) != 0;
	coder->concatenated = (flags & LZMA_CONCATENATED) != 0;
	coder->first_stream = true;

	return lzip_decoder_reset(coder, allocator);
}


extern LZMA_API(lzma_ret)
lzma_lzip_decoder(lzma_stream *strm, uint64_t memlimit, uint32_t flags)
{
	lzma_next_strm_init(lzma_lzip_decoder_init, strm, memlimit, flags);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}
