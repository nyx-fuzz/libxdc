/*
Copyright (c) 2020 Sergej Schumilo, Cornelius Aschermann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "cfg.h"

bool disassembler_cfg_init(disassembler_cfg_t* res, uint32_t size){
    res->br1 = (cfg_branch_t*)calloc(size, sizeof(cfg_branch_t));
    res->br2 = (cfg_branch_t*)calloc(size, sizeof(cfg_branch_t));
    res->base_addr = (uint64_t*)calloc(size, sizeof(uint64_t));
    res->cofi_addr = (uint64_t*)calloc(size, sizeof(uint64_t));
    res->br1_addr = (uint64_t*)calloc(size, sizeof(uint64_t));
    res->br2_addr = (uint64_t*)calloc(size, sizeof(uint64_t));
    res->max_size = size;
    res->next_node_id = NODE_OOB+1;
    res->next_bitmap_id=0;
    res->ip_to_node_id = kh_init(ADDR0);

    if ( !(res->type = (cofi_type*)calloc(size, sizeof(cofi_type))) )
        return false;

    res->type[NODE_PAGE_FAULT]=PAGE_CACHE_FAILED; //NODE_PAGE_FAULT is used to indicate that disassembly failed due to missing memory
    res->type[NODE_OOB]=OUT_OF_BOUNDS;

    return true;
}

void disassembler_cfg_destroy(disassembler_cfg_t* self){
    free(self->br1);
    self->br1 = NULL;
    free(self->br2);
    self->br2 = NULL;
    free(self->base_addr);
    self->base_addr = NULL;
    free(self->cofi_addr);
    self->cofi_addr = NULL;
    free(self->br1_addr);
    self->br1_addr = NULL;
    free(self->br2_addr);
    self->br2_addr = NULL;
    free(self->type);
    self->type = NULL;
    kh_destroy(ADDR0, self->ip_to_node_id);
}

void disassembler_cfg_inspect(disassembler_cfg_t* self, node_id_t nid){
    if(nid == NODE_NOT_DEFINED){
        printf("(NODE_NOT_DEFINED)\n");
        return;
    }
    if(nid== NODE_PAGE_FAULT){
        printf("(NODE_PAGE_FAULT)\n");
        return;
    }
    if(nid== NODE_OOB){
        printf("(NODE_OOB)\n");
        return;
    }
    assert(nid < self->next_node_id);
    switch(self->type[nid]){
        case COFI_TYPE_CONDITIONAL_BRANCH:
            printf("NODE_COND{ taken: ");
            if(self->br1[nid].node_id == NODE_NOT_DEFINED){
                printf("(NODE_NOT_DEFINED)");
            }else{
                printf(" %d", self->br1[nid].node_id);
            }
            printf("(0x%lx)",self->br1_addr[nid]);
            printf(", not_taken: ");
            if(self->br2[nid].node_id == NODE_NOT_DEFINED){
                printf("(NODE_NOT_DEFINED)");
            }else{
                printf(" %d", self->br2[nid].node_id);
            }
            printf("(0x%lx)",self->br2_addr[nid]);
            break;
	    case COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH:
            printf("NODE_UNCOND_DIRECT{ to: ");
            if(self->br1[nid].node_id == NODE_NOT_DEFINED){
                printf("(NODE_NOT_DEFINED)");
            }else{
                printf(" %d", self->br1[nid].node_id);
            }
            printf("(0x%lx)",self->br1_addr[nid]);
            break;
	    case COFI_TYPE_INDIRECT_BRANCH: 
            printf("NODE_INDIRECT{ ");
            break;
	    case COFI_TYPE_NEAR_RET: 
            printf("NODE_RET{ ");
            break;
	    case COFI_TYPE_FAR_TRANSFERS:
            printf("NODE_FAR{ ");
            break;
        default:
            assert(0);
        //NO_COFI_TYPE,
        //DISASSEMBLY_PENDING,
        //OUT_OF_BOUNDS,
        //INFINITE_LOOP,
        //PAGE_CACHE_FAILED,
    }
    printf(" id: %d, at: 0x%lx, cofi_addr: 0x%lx }\n", nid, self->base_addr[nid], self->cofi_addr[nid]);
}


void disassmembler_cfg_resize(disassembler_cfg_t* self){
    assert(self->max_size <= 0x7fffffff);
    uint32_t size = self->max_size*2;
    self->br1 = (cfg_branch_t*)reallocarray(self->br1, size, sizeof(cfg_branch_t));
    self->br2 = (cfg_branch_t*)reallocarray(self->br2, size, sizeof(cfg_branch_t));
    self->base_addr = (uint64_t*)reallocarray(self->base_addr, size, sizeof(uint64_t));
    self->cofi_addr = (uint64_t*)reallocarray(self->cofi_addr, size, sizeof(uint64_t));
    self->br1_addr = (uint64_t*)reallocarray(self->br1_addr, size, sizeof(uint64_t));
    self->br2_addr = (uint64_t*)reallocarray(self->br2_addr, size, sizeof(uint64_t));
    self->type = (cofi_type*)reallocarray(self->type, size, sizeof(cofi_type));
    self->max_size = size;
}

uint32_t disassembler_cfg_get_node_id(disassembler_cfg_t* self, uint64_t ip) {
    khiter_t k;
	k = kh_get(ADDR0, self->ip_to_node_id, ip); 
	if(k != kh_end(self->ip_to_node_id)){
		return kh_value(self->ip_to_node_id, k); 
	} 
	return NODE_NOT_DEFINED;
}


static inline node_id_t disassembler_cfg_next_nid(disassembler_cfg_t* self){
    return self->next_node_id++;
}

static inline node_id_t disassembler_cfg_next_bid(disassembler_cfg_t* self){
    return self->next_bitmap_id++;
}

node_id_t disassembler_cfg_add_node(disassembler_cfg_t* self, uint64_t base_ip,  uint64_t cofi_ip, cofi_type type){
    node_id_t new_nid = disassembler_cfg_next_nid(self);
    self->base_addr[new_nid] = base_ip; 
    self->cofi_addr[new_nid] = cofi_ip; 
    self->type[new_nid] = type;
    
    int ret;
	khiter_t k;
	k = kh_put(ADDR0, self->ip_to_node_id, base_ip, &ret); 
	kh_value(self->ip_to_node_id, k) = new_nid;
    return new_nid;
}

node_id_t disassembler_cfg_prefix_node(disassembler_cfg_t* self, uint64_t base_address, node_id_t old_node){
    node_id_t res_nid = disassembler_cfg_add_node(self, base_address, self->cofi_addr[old_node], self->type[old_node]);
    self->br1[res_nid] = self->br1[old_node];
    if(self->br1[res_nid].node_id != NODE_NOT_DEFINED){
        self->br1[res_nid].bitmap_id = disassembler_cfg_next_bid(self);
    }
    self->br2[res_nid] = self->br2[old_node];
    if(self->br2[res_nid].node_id != NODE_NOT_DEFINED){
        self->br2[res_nid].bitmap_id = disassembler_cfg_next_bid(self);
    }
    self->br1_addr[res_nid] = self->br1_addr[old_node];
    self->br2_addr[res_nid] = self->br2_addr[old_node];
    return res_nid;
}

void disassembler_cfg_add_br1_addr(disassembler_cfg_t* self, node_id_t node, uint64_t target){
    
    self->br1_addr[node]=target;

    node_id_t target_nid = disassembler_cfg_get_node_id(self, target);
    self->br1[node].node_id = target_nid;
    if(target_nid != NODE_NOT_DEFINED){
        self->br1[node].bitmap_id = disassembler_cfg_next_bid(self);
    }
}

void disassembler_cfg_add_br2_addr(disassembler_cfg_t* self, node_id_t node, uint64_t target){
    
    self->br2_addr[node]=target;
    node_id_t target_nid = disassembler_cfg_get_node_id(self, target);
    self->br2[node].node_id = target_nid;
    if(target_nid != NODE_NOT_DEFINED){
        self->br2[node].bitmap_id = disassembler_cfg_next_bid(self);
    }
}

void disassembler_cfg_add_br1_nid(disassembler_cfg_t* self, node_id_t node, node_id_t target_nid){
	if( target_nid != NODE_NOT_DEFINED && target_nid != NODE_PAGE_FAULT){
		self->br1[node].node_id = target_nid;
		self->br1[node].bitmap_id = disassembler_cfg_next_bid(self);
	}
}

void disassembler_cfg_add_br2_nid(disassembler_cfg_t* self, node_id_t node, node_id_t target_nid){
	if( target_nid != NODE_NOT_DEFINED && target_nid != NODE_PAGE_FAULT ){
		self->br2[node].node_id = target_nid;
		self->br2[node].bitmap_id = disassembler_cfg_next_bid(self);
	}
}
