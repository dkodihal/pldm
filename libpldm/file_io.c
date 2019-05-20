#include "file_io.h"
#include <endian.h>
#include <string.h>

int decode_rw_file_memory_req(const struct pldm_msg_payload *msg,
			      uint32_t *fileHandle, uint32_t *offset,
			      uint32_t *length, uint64_t *address)
{
	if (msg == NULL || fileHandle == NULL || offset == NULL ||
	    length == NULL || address == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (msg->payload_length != PLDM_RW_FILE_MEM_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	const uint8_t *start = msg->payload;
	*fileHandle = le32toh(*((uint32_t *)start));
	*offset = le32toh(*((uint32_t *)(start + sizeof(*fileHandle))));
	*length = le32toh(
	    *((uint32_t *)(start + sizeof(*fileHandle) + sizeof(*offset))));
	*address = le64toh(*((uint64_t *)(start + sizeof(*fileHandle) +
					  sizeof(*offset) + sizeof(*length))));

	return PLDM_SUCCESS;
}

int encode_rw_file_memory_resp(uint8_t instance_id, uint8_t command,
			       uint8_t completion_code, uint32_t length,
			       struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_FILE_IO;
	header.command = command;
	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	msg->body.payload[0] = completion_code;
	if (msg->body.payload[0] == PLDM_SUCCESS) {
		uint8_t *dst = msg->body.payload + sizeof(msg->body.payload[0]);
		length = htole32(length);
		memcpy(dst, &length, sizeof(length));
	}

	return PLDM_SUCCESS;
}

int decode_get_file_table_req(const struct pldm_msg_payload *msg,
			      uint32_t *transfer_handle,
			      uint8_t *transfer_opflag, uint8_t *table_type)
{
	if (msg == NULL || transfer_handle == NULL || transfer_opflag == NULL ||
	    table_type == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (msg->payload_length != PLDM_GET_FILE_TABLE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	const uint8_t *start = msg->payload;
	*transfer_handle = le32toh(*((uint32_t *)start));
	*transfer_opflag = *(start + sizeof(*transfer_handle));
	*table_type =
	    *(start + sizeof(*transfer_handle) + sizeof(*transfer_opflag));

	return PLDM_SUCCESS;
}

int encode_get_file_table_resp(uint8_t instance_id, uint8_t completion_code,
			       uint32_t next_transfer_handle,
			       uint8_t transfer_flag, const uint8_t *table_data,
			       size_t table_size, struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_FILE_IO;
	header.command = PLDM_GET_FILE_TABLE;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	msg->body.payload[0] = completion_code;

	if (msg->body.payload[0] == PLDM_SUCCESS) {
		uint8_t *dst = msg->body.payload + sizeof(completion_code);
		next_transfer_handle = htole32(next_transfer_handle);
		memcpy(dst, &next_transfer_handle,
		       sizeof(next_transfer_handle));
		dst += sizeof(next_transfer_handle);

		memcpy(dst, &transfer_flag, sizeof(transfer_flag));
		dst += sizeof(transfer_flag);

		memcpy(dst, table_data, table_size);
	}

	return PLDM_SUCCESS;
}
