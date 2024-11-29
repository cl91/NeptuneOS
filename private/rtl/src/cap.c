#include <nt.h>
#include <structures_gen.h>

PCSTR RtlDbgCapTypeToStr(cap_tag_t Type)
{
    switch (Type) {
    case cap_null_cap:
	return "null";
    case cap_untyped_cap:
	return "untyped";
    case cap_endpoint_cap:
	return "endpoint";
    case cap_notification_cap:
	return "notification";
    case cap_reply_cap:
	return "reply";
    case cap_cnode_cap:
	return "cnode";
    case cap_thread_cap:
	return "thread";
    case cap_frame_cap:
	return "frame";
    case cap_page_table_cap:
	return "page-table";
    case cap_asid_control_cap:
	return "asid-control";
    case cap_asid_pool_cap:
	return "asid-pool";
    case cap_irq_control_cap:
	return "irq-control";
    case cap_irq_handler_cap:
	return "irq-handler";
    case cap_zombie_cap:
	return "zombie";
    case cap_domain_cap:
	return "domain";
#ifdef CONFIG_IOMMU
    case cap_io_space_cap:
	return "io-space";
    case cap_io_page_table_cap:
	return "io-page-table";
#endif
#if defined(_M_IX86) || defined(_M_AMD64)
    case cap_page_directory_cap:
	return "page-directory";
    case cap_io_port_cap:
	return "io-port";
    case cap_io_port_control_cap:
	return "io-port-control";
#endif
#ifdef _M_AMD64
    case cap_pdpt_cap:
	return "pdpt";
    case cap_pml4_cap:
	return "pml4";
#endif
#ifdef _M_ARM64
    case cap_vspace_cap:
	return "vspace";
#endif
    }
    return "unknown";
}
