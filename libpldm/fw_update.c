#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <string.h>

#include "fw_update.h"


int encode_fw_request_update_req(uint8_t instance_id, uint32_t max_transfer_size,
			   uint16_t num_of_component, uint8_t max_outstanding_transfer_req,
			   uint16_t package_data_length, uint8_t compImage_set_versionString_type, 
                           uint8_t compImage_set_versionString_length, 
                           uint8_t *compImage_set_versionString, size_t versionLen, struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FIRMWARE_UPDATE;
	header.command = PLDM_FW_REQ_UPDATE;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_fw_request_update_req *request =
	    (struct pldm_fw_request_update_req *)msg->payload;

        request->max_transfer_size = max_transfer_size;
        request->num_of_component = num_of_component;
        request->max_outstanding_transfer_req = max_outstanding_transfer_req;
        request->package_data_length = package_data_length; 
        request->compImage_set_versionString_type = compImage_set_versionString_type;
        request->compImage_set_versionString_length = compImage_set_versionString_length;
        memcpy(request->compImage_set_versionString, compImage_set_versionString, versionLen); 
  
	return PLDM_SUCCESS;
}

int encode_fw_request_update_resp(uint8_t instance_id, uint8_t completion_code,
			    uint16_t firmwaredev_metadata_length,
			    uint8_t FD_GetPackage_data_command,
			    struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;
	struct pldm_fw_request_update_resp *response =
	    (struct pldm_fw_request_update_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {

		header.msg_type = PLDM_RESPONSE;
		header.instance = instance_id;
		header.pldm_type = PLDM_FIRMWARE_UPDATE;
		header.command = PLDM_FW_REQ_UPDATE;

		if ((rc = pack_pldm_header(&header, &(msg->hdr))) >
		    PLDM_SUCCESS) {
			return rc;
		}
		response->firmwaredev_metadata_length = firmwaredev_metadata_length;
		response->FD_GetPackage_data_command = FD_GetPackage_data_command;
	}
	return PLDM_SUCCESS;
}

int decode_fw_request_update_req(const struct pldm_msg *msg, size_t payload_length,
			   uint32_t *max_transfer_size, uint16_t *num_of_component, uint8_t *max_outstanding_transfer_req,
			   uint16_t *package_data_length, uint8_t *compImage_set_versionString_type, 
                           uint8_t *compImage_set_versionString_length, 
                           uint8_t *compImage_set_versionString, size_t versionLen)
{

	if (payload_length != PLDM_FW_REQUEST_UPDATE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_request_update_req *request =
	    (struct pldm_fw_request_update_req *)msg->payload;

        
        *max_transfer_size = request->max_transfer_size;
        *num_of_component  = request->num_of_component;
        *max_outstanding_transfer_req = request->max_outstanding_transfer_req;
        *package_data_length = request->package_data_length;
        *compImage_set_versionString_type  =  request->compImage_set_versionString_type;
        *compImage_set_versionString_length = request->compImage_set_versionString_length;
        memcpy(compImage_set_versionString, request->compImage_set_versionString, versionLen); 
  
	return PLDM_SUCCESS;
}

int decode_fw_request_update_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint16_t *firmwaredev_metadata_length,
			    uint8_t *FD_GetPackage_data_command)
{
	if (msg == NULL || firmwaredev_metadata_length == NULL ||
	    FD_GetPackage_data_command == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_FW_REQUEST_UPDATE_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_request_update_resp *response =
	    (struct pldm_fw_request_update_resp *)msg->payload;

	*firmwaredev_metadata_length = response->firmwaredev_metadata_length;
	*FD_GetPackage_data_command = response->FD_GetPackage_data_command;

	return PLDM_SUCCESS;
}


int encode_fw_pass_component_table_req(uint8_t instance_id, uint8_t transfer_flag,
			   uint16_t comp_classification, uint16_t comp_identifier,
			   uint8_t comp_classificationIdx, uint32_t comp_comparision_stamp, 
                           uint8_t component_versionString_type, 
                           uint8_t component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen, struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FIRMWARE_UPDATE;
	header.command = PLDM_FW_PASS_COMPONENT_TABLE;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_fw_pass_component_table_req *request =
	    (struct pldm_fw_pass_component_table_req *)msg->payload;

        request->transfer_flag = transfer_flag;
        request->comp_classification = comp_classification;
        request->comp_identifier = comp_identifier;
        request->comp_classificationIdx = comp_classificationIdx;
        request->comp_comparision_stamp = comp_comparision_stamp; 
        request->component_versionString_type = component_versionString_type;
        request->component_versionString_length = component_versionString_length;
        memcpy(request->component_versionString, component_versionString, versionLen); 
  
	return PLDM_SUCCESS;
}


int encode_fw_pass_component_table_resp(uint8_t instance_id, uint8_t completion_code,
			    uint8_t comp_response,
			    uint8_t comp_responseCode,
			    struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;
	struct pldm_fw_pass_component_table_resp *response =
	    (struct pldm_fw_pass_component_table_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {

		header.msg_type = PLDM_RESPONSE;
		header.instance = instance_id;
		header.pldm_type = PLDM_FIRMWARE_UPDATE;
		header.command = PLDM_FW_PASS_COMPONENT_TABLE;

		if ((rc = pack_pldm_header(&header, &(msg->hdr))) >
		    PLDM_SUCCESS) {
			return rc;
		}
		response->comp_response = comp_response;
		response->comp_responseCode = comp_responseCode;
	}
	return PLDM_SUCCESS;
}

int decode_fw_pass_component_table_req(const struct pldm_msg *msg, size_t payload_length,
			   uint8_t *transfer_flag, uint16_t *comp_classification, uint16_t *comp_identifier,
			   uint8_t *comp_classificationIdx, uint32_t *comp_comparision_stamp, uint8_t *component_versionString_type,
                           uint8_t *component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen)
{

	if (payload_length != PLDM_FW_PASS_COMP_TBL_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_pass_component_table_req *request =
	    (struct pldm_fw_pass_component_table_req *)msg->payload;

        
        *transfer_flag = request->transfer_flag;
        *comp_classification  = request->comp_classification;
        *comp_identifier = request->comp_identifier;
        *comp_classificationIdx = request->comp_classificationIdx;
        *comp_comparision_stamp = request->comp_comparision_stamp;
        *component_versionString_type  =  request->component_versionString_type;
        *component_versionString_length = request->component_versionString_length;
        memcpy(component_versionString, request->component_versionString, versionLen); 
  
	return PLDM_SUCCESS;
}

int decode_fw_pass_component_table_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint8_t *comp_response,
			    uint8_t *comp_responseCode)
{
	if (msg == NULL || comp_response == NULL ||
	    comp_responseCode == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_FW_PASS_COMP_TBL_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_pass_component_table_resp *response =
	    (struct pldm_fw_pass_component_table_resp *)msg->payload;

	*comp_response = response->comp_response;
	*comp_responseCode = response->comp_responseCode;

	return PLDM_SUCCESS;
}


int encode_fw_update_component_req(uint8_t instance_id,
			   uint16_t comp_classification, uint16_t comp_identifier,
			   uint8_t comp_classificationIdx, uint32_t comp_comparision_stamp,
                           uint32_t comp_image_size, uint32_t update_option_flags, 
                           uint8_t component_versionString_type, 
                           uint8_t component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen, struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FIRMWARE_UPDATE;
	header.command = PLDM_FW_UPDATE_COMPONENT;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_fw_update_component_req *request =
	    (struct pldm_fw_update_component_req *)msg->payload;
        
        request->comp_classification = comp_classification;
        request->comp_identifier = comp_identifier;
        request->comp_classificationIdx = comp_classificationIdx;
        request->comp_comparision_stamp = comp_comparision_stamp; 
        request->comp_image_size = comp_image_size; 
        request->update_option_flags = update_option_flags; 
        request->component_versionString_type = component_versionString_type;
        request->component_versionString_length = component_versionString_length;
        memcpy(request->component_versionString, component_versionString, versionLen); 
  
	return PLDM_SUCCESS;
}


int encode_fw_update_component_resp(uint8_t instance_id, uint8_t completion_code,
			    uint8_t comp_combatibility_response,
			    uint8_t comp_combatibility_responseCode,
			    uint32_t update_option_flags_enabled,
			    uint16_t estimatedTime_beforeSend_ReqFirmware_data,
			    struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;
	struct pldm_fw_update_component_resp *response =
	    (struct pldm_fw_update_component_resp *)msg->payload;
	response->completion_code = completion_code;

	if (response->completion_code == PLDM_SUCCESS) {

		header.msg_type = PLDM_RESPONSE;
		header.instance = instance_id;
		header.pldm_type = PLDM_FIRMWARE_UPDATE;
		header.command = PLDM_FW_UPDATE_COMPONENT;

		if ((rc = pack_pldm_header(&header, &(msg->hdr))) >
		    PLDM_SUCCESS) {
			return rc;
		}
		response->comp_combatibility_response = comp_combatibility_response;
		response->comp_combatibility_responseCode = comp_combatibility_responseCode;
		response->update_option_flags_enabled = update_option_flags_enabled;
		response->estimatedTime_beforeSend_ReqFirmware_data = estimatedTime_beforeSend_ReqFirmware_data;
	}
	return PLDM_SUCCESS;
}

int decode_fw_update_component_req(const struct pldm_msg *msg, size_t payload_length,
			   uint16_t *comp_classification, uint16_t *comp_identifier,
			   uint8_t *comp_classificationIdx, uint32_t *comp_comparision_stamp, 
			   uint32_t *comp_image_size, uint32_t *update_option_flags, 
                           uint8_t *component_versionString_type,
                           uint8_t *component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen)
{

	if (payload_length != PLDM_FW_UPDATE_COMP_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_update_component_req *request =
	    (struct pldm_fw_update_component_req *)msg->payload;

        *comp_classification  = request->comp_classification;
        *comp_identifier = request->comp_identifier;
        *comp_classificationIdx = request->comp_classificationIdx;
        *comp_comparision_stamp = request->comp_comparision_stamp;
        *comp_image_size = request->comp_image_size;
        *update_option_flags = request->update_option_flags;
        *component_versionString_type  =  request->component_versionString_type;
        *component_versionString_length = request->component_versionString_length;
        memcpy(component_versionString, request->component_versionString, versionLen); 
  
	return PLDM_SUCCESS;
}

int decode_fw_update_component_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint8_t *comp_combatibility_response,
			    uint8_t *comp_combatibility_responseCode, 
                            uint32_t *update_option_flags_enabled, 
                            uint16_t *estimatedTime_beforeSend_ReqFirmware_data)
{
	if (msg == NULL || comp_combatibility_response == NULL ||
	    comp_combatibility_response == NULL || update_option_flags_enabled == NULL ||
            estimatedTime_beforeSend_ReqFirmware_data == NULL ||
            completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_FW_UPDATE_COMP_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_update_component_resp *response =
	    (struct pldm_fw_update_component_resp *)msg->payload;

	*comp_combatibility_response = response->comp_combatibility_response;
	*comp_combatibility_responseCode = response->comp_combatibility_responseCode;
        *update_option_flags_enabled = response->update_option_flags_enabled;
        *estimatedTime_beforeSend_ReqFirmware_data = response->estimatedTime_beforeSend_ReqFirmware_data;

	return PLDM_SUCCESS;
}


int encode_fw_activate_firmware_req(uint8_t instance_id, bool selfCont_Activation_req,
			   struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FIRMWARE_UPDATE;
	header.command = PLDM_FW_ACTIVATE_FIRMWARE;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_fw_activate_firmware_req *request =
	    (struct pldm_fw_activate_firmware_req *)msg->payload;

        request->selfCont_Activation_req = selfCont_Activation_req;

	return PLDM_SUCCESS;
}


int encode_fw_activate_firmware_resp(uint8_t instance_id, uint8_t completion_code,
			    uint16_t estimatedTime_selfCont_Activation,
			    struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;
	struct pldm_fw_activate_firmware_resp *response =
	    (struct pldm_fw_activate_firmware_resp *)msg->payload;
	response->completion_code = completion_code;
	if (response->completion_code == PLDM_SUCCESS) {

		header.msg_type = PLDM_RESPONSE;
		header.instance = instance_id;
		header.pldm_type = PLDM_FIRMWARE_UPDATE;
		header.command = PLDM_FW_ACTIVATE_FIRMWARE;

		if ((rc = pack_pldm_header(&header, &(msg->hdr))) >
		    PLDM_SUCCESS) {
			return rc;
		}
		response->estimatedTime_selfCont_Activation = estimatedTime_selfCont_Activation;
	}
	return PLDM_SUCCESS;
}

int decode_fw_activate_firmware_req(const struct pldm_msg *msg, size_t payload_length,
                           bool *selfCont_Activation_req) 
{

	if (payload_length != PLDM_FW_ACTIVATE_FIRMWARE_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_activate_firmware_req *request =
	    (struct pldm_fw_activate_firmware_req *)msg->payload;

        
        *selfCont_Activation_req = request->selfCont_Activation_req;
  
	return PLDM_SUCCESS;
}

int decode_fw_activate_firmware_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint16_t *estimatedTime_selfCont_Activation)
{
	if (msg == NULL || estimatedTime_selfCont_Activation == NULL ||
	    completion_code == NULL) {
                return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_FW_ACTIVATE_FIRMWARE_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_activate_firmware_resp *response =
	    (struct pldm_fw_activate_firmware_resp *)msg->payload;

	*estimatedTime_selfCont_Activation = response->estimatedTime_selfCont_Activation;

	return PLDM_SUCCESS;
}


int encode_fw_cancel_update_req(uint8_t instance_id,  struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FIRMWARE_UPDATE;
	header.command = PLDM_FW_CANCEL_UPDATE;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_fw_activate_firmware_req *request =
	    (struct pldm_fw_activate_firmware_req *)msg->payload;


	return PLDM_SUCCESS;
}


int decode_fw_cancel_update_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code)
{
	if (msg == NULL ||  completion_code == NULL) {
                return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_FW_CANCEL_UPDATE_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_fw_activate_firmware_resp *response =
	    (struct pldm_fw_activate_firmware_resp *)msg->payload;

	return PLDM_SUCCESS;
}

