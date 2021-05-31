#ifndef FW_UPDATE_H
#define FW_UPDATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <asm/byteorder.h>
#include <stddef.h>
#include <stdint.h>

#include "base.h"
#include "utils.h"

#define PLDM_FW_REQUEST_UPDATE_REQ_BYTES 28
#define PLDM_FW_REQUEST_UPDATE_RESP_BYTES 4
#define PLDM_FW_PASS_COMP_TBL_REQ_BYTES 25
#define PLDM_FW_PASS_COMP_TBL_RESP_BYTES 3
#define PLDM_FW_UPDATE_COMP_REQ_BYTES 25
#define PLDM_FW_UPDATE_COMP_RESP_BYTES 9
#define PLDM_FW_ACTIVATE_FIRMWARE_REQ_BYTES 1
#define PLDM_FW_ACTIVATE_FIRMWARE_RESP_BYTES 3
#define PLDM_FW_CANCEL_UPDATE_REQ_BYTES 0
#define PLDM_FW_CANCEL_UPDATE_RESP_BYTES 1


#define FRU_TABLE_CHECKSUM_SIZE 4

/** @brief PLDM FW UPDATE commands
 */
enum pldm_fw_update_commands {
	PLDM_FW_REQ_UPDATE = 0X10,
	PLDM_FW_PASS_COMPONENT_TABLE = 0X13,
	PLDM_FW_UPDATE_COMPONENT = 0X14,
	PLDM_FW_ACTIVATE_FIRMWARE = 0X1a,
	PLDM_FW_CANCEL_UPDATE = 0X1d
};

struct pldm_fw_request_update_req {

        uint32_t max_transfer_size;
        uint16_t num_of_component; 
        uint8_t max_outstanding_transfer_req;
        uint16_t package_data_length;
        uint8_t compImage_set_versionString_type;
        uint8_t compImage_set_versionString_length;
        uint8_t compImage_set_versionString[1];

} __attribute__((packed));
        
struct pldm_fw_request_update_resp {

        uint8_t completion_code;       
        uint16_t firmwaredev_metadata_length;                                       
        uint8_t FD_GetPackage_data_command;         

} __attribute__((packed));

struct pldm_fw_pass_component_table_req {

        uint8_t transfer_flag;
        uint16_t comp_classification; 
        uint16_t comp_identifier;
        uint8_t comp_classificationIdx;
        uint32_t comp_comparision_stamp;
        uint8_t component_versionString_type;
        uint8_t component_versionString_length;
        uint8_t component_versionString[1];

} __attribute__((packed));
        
struct pldm_fw_pass_component_table_resp {

        uint8_t completion_code;       
        uint8_t comp_response;                                       
        uint8_t comp_responseCode;         

} __attribute__((packed));


struct pldm_fw_update_component_req {

        uint16_t comp_classification; 
        uint16_t comp_identifier;
        uint8_t comp_classificationIdx;
        uint32_t comp_comparision_stamp;
        uint32_t comp_image_size;
        uint32_t update_option_flags;
        uint8_t component_versionString_type;
        uint8_t component_versionString_length;
        uint8_t component_versionString[1];

} __attribute__((packed));
        
struct pldm_fw_update_component_resp {

        uint8_t completion_code;       
        uint8_t comp_combatibility_response;                                       
        uint8_t comp_combatibility_responseCode;                                       
        uint32_t update_option_flags_enabled;
        uint16_t estimatedTime_beforeSend_ReqFirmware_data;         

} __attribute__((packed));
        

struct pldm_fw_activate_firmware_req {

        bool selfCont_Activation_req; 

} __attribute__((packed));
        
struct pldm_fw_activate_firmware_resp {

        uint8_t completion_code;       
        uint16_t estimatedTime_selfCont_Activation;         

} __attribute__((packed));
        
int encode_fw_request_update_req(uint8_t instance_id, uint32_t max_transfer_size,
                           uint16_t num_of_component, uint8_t max_outstanding_transfer_req,
                           uint16_t package_data_length, uint8_t compImage_set_versionString_type,
                           uint8_t compImage_set_versionString_length,
                           uint8_t *compImage_set_versionString, size_t versionLen, struct pldm_msg *msg);

int encode_fw_request_update_resp(uint8_t instance_id, uint8_t completion_code,
                            uint16_t firmwaredev_metadata_length,
                            uint8_t FD_GetPackage_data_command,
                            struct pldm_msg *msg);

int decode_fw_request_update_req(const struct pldm_msg *msg, size_t payload_length,
                           uint32_t *max_transfer_size, uint16_t *num_of_component, uint8_t *max_outstanding_transfer_req,
                           uint16_t *package_data_length, uint8_t *compImage_set_versionString_type,
                           uint8_t *compImage_set_versionString_length,
                           uint8_t *compImage_set_versionString, size_t versionLen);

int decode_fw_request_update_resp(const struct pldm_msg *msg, size_t payload_length,
                            uint8_t *completion_code,
                            uint16_t *firmwaredev_metadata_length,
                            uint8_t *FD_GetPackage_data_command);

int encode_fw_pass_component_table_req(uint8_t instance_id, uint8_t transfer_flag,
			   uint16_t comp_classification, uint16_t comp_identifier,
			   uint8_t comp_classificationIdx, uint32_t comp_comparision_stamp, 
                           uint8_t component_versionString_type, 
                           uint8_t component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen, struct pldm_msg *msg);

int encode_fw_pass_component_table_resp(uint8_t instance_id, uint8_t completion_code,
			    uint8_t comp_response,
			    uint8_t comp_responseCode,
			    struct pldm_msg *msg);

int decode_fw_pass_component_table_req(const struct pldm_msg *msg, size_t payload_length,
			   uint8_t *transfer_flag, uint16_t *comp_classification, uint16_t *comp_identifier,
			   uint8_t *comp_classificationIdx, uint32_t *comp_comparision_stamp, uint8_t *component_versionString_type,
                           uint8_t *component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen);

int decode_fw_pass_component_table_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint8_t *comp_response,
			    uint8_t *comp_responseCode);


int encode_fw_update_component_req(uint8_t instance_id,
			   uint16_t comp_classification, uint16_t comp_identifier,
			   uint8_t comp_classificationIdx, uint32_t comp_comparision_stamp,
                           uint32_t comp_image_size, uint32_t update_option_flags, 
                           uint8_t component_versionString_type, 
                           uint8_t component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen, struct pldm_msg *msg);

int encode_fw_update_component_resp(uint8_t instance_id, uint8_t completion_code,
			    uint8_t comp_combatibility_response,
			    uint8_t comp_combatibility_responseCode,
			    uint32_t update_option_flags_enabled,
			    uint16_t estimatedTime_beforeSend_ReqFirmware_data,
			    struct pldm_msg *msg);


int decode_fw_update_component_req(const struct pldm_msg *msg, size_t payload_length,
			   uint16_t *comp_classification, uint16_t *comp_identifier,
			   uint8_t *comp_classificationIdx, uint32_t *comp_comparision_stamp, 
			   uint32_t *comp_image_size, uint32_t *update_option_flags, 
                           uint8_t *component_versionString_type,
                           uint8_t *component_versionString_length, 
                           uint8_t *component_versionString, size_t versionLen);

int decode_fw_update_component_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint8_t *comp_combatibility_response,
			    uint8_t *comp_combatibility_responseCode, 
                            uint32_t *update_option_flags_enabled, 
                            uint16_t *estimatedTime_beforeSend_ReqFirmware_data);

int encode_fw_activate_firmware_req(uint8_t instance_id, bool selfCont_Activation_req,
			   struct pldm_msg *msg);

int encode_fw_activate_firmware_resp(uint8_t instance_id, uint8_t completion_code,
			    uint16_t estimatedTime_selfCont_Activation,
			    struct pldm_msg *msg);

int decode_fw_activate_firmware_req(const struct pldm_msg *msg, size_t payload_length,
                           bool *selfCont_Activation_req);

int decode_fw_activate_firmware_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint16_t *estimatedTime_selfCont_Activation);

int encode_fw_cancel_update_req(uint8_t instance_id,  struct pldm_msg *msg);

int decode_fw_cancel_update_resp(const struct pldm_msg *msg, size_t payload_length,
                            uint8_t *completion_code);


#ifdef __cplusplus
}
#endif

#endif
