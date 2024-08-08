#include <tofino/intrinsic_metadata.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/constants.p4>
#include "includes/headers.p4"
#include "includes/parser.p4"

#include "includes/registers.p4"
#include "includes/tables.p4"
#include "includes/actions.p4"
#include "includes/common.p4"

// grep -r -n "p4ml_meta_t" .
// mdata -> parser.p4#3 -> headers.p4#138 
field_list p4ml_resubmit_list{
	mdata.agtr_time;	
}

action do_resubmit(){
    // resubmit 是一个用于重新提交数据包的操作，它允许在数据包处理管道的某个阶段中将数据包重新提交到管道的起始位置，以便重新进行处理
    // 例如，在更新了某些元数据或状态信息后，可能需要对数据包进行不同的处理，此时可以使用 resubmit 重新提交数据包以应用这些变化
    // resubmit 可以指定保留的字段列表，以确保重新提交时某些重要信息不会丢失
    // 在下面代码中，mdata.agtr_time 是需要保留的元数据字段；在重新提交数据包时，resubmit 会确保该字段的值被保留并传递到下一个处理周期
	resubmit(p4ml_resubmit_list);
    
}

table p4ml_resubmit{
	actions{
		do_resubmit;
	}
	default_action: do_resubmit();
	size: 1;

}

// 这一块代码应该是p4_16中查表逻辑match-action部分
// parser和deparser逻辑另写在其他文件中
// 故阅读代码时应先查看parser.p4部分
control ingress 
{
    // p4ml_entries为待聚合的梯度分片，其定义在 parser.p4#4 -> headers.p4#86
    // 此处p4ml_entries的值来自 parser.p4#73
    if (valid(p4ml_entries)) {

            // p4ml和ipv4由parser解析获得
            // 若ecn有效，则告知交换机当前网络出现了拥塞
            // common.p4#228
            if (ipv4.ecn == 3 or p4ml.ECN == 1) {
                apply(setup_ecn_table);
            }
            // 判断当前数据包是否为应答包
            if (p4ml.isACK == 1) {
                // p4ml.overflow用于指示交换机处的registor是否发生了浮点溢出
                if (p4ml.overflow == 1 and p4ml.isResend == 0) {

                } else {
                    // 疑问：这里的逻辑看起来似乎是只能处理一个聚合任务？appID_and_Seq的赋值在 p4ml.p4#98 进行

                    // 当前包为应答包，若寄存器appID_and_Seq中的值与p4ml_agtr_index.agtr相同，则表明聚合已经完成
                    // 故应该释放寄存器appID_and_Seq，并将p4ml.appIDandSeqNum复制到mdata.isMyAppIDandMyCurrentSeq中
                    // common.p4#443 -> common.p4#225 -> common.p4#102 
                    apply(clean_appID_and_seq_table);
                    
                    if (mdata.isMyAppIDandMyCurrentSeq != 0) {
                        /* Clean */   
                        apply(clean_bitmap_table); // 将寄存器bitmap清零，common.p4#402 -> #207 -> #21
                        apply(clean_ecn_table); // 将寄存器ecn_register清零，common.p4#393 -> #203 -> #15
                        apply(clean_agtr_time_table); // 将寄存器agtr_time清零，common.p4#385 -> #199 -> #9
                        // apply(cleanEntry1);
                    }
                }

                /* Multicast Back */
                // 疑问：resubmit_flag是1为假、0为真吗？
                if(ig_intr_md.resubmit_flag == 1) {
                    // 疑问：控制面如何下发multicast_table中的表项
                    apply(multicast_table); // common.p4#371
                } else {
                    apply(p4ml_resubmit); //p4ml.p4#27
                }
                
            } else {
                // 若数据包为梯度分片

                if (p4ml.overflow == 1) {
                    // 疑问：此处的overflow是由谁标记的？
                    apply(outPort_table);   // 对于已经溢出的梯度，则直接丢弃， common.p4#344
                } else {
                    // 若未发生浮点溢出
                    if (p4ml.isResend == 1) {
                        // 若该梯度分片是重新发送的，并且属于当前appID_and_Seq寄存器记录的DT任务
                        // 则清空appID_and_Seq，并将原先appID_and_Seq的值放入mdata.isMyAppIDandMyCurrentSeq中
                        apply(appID_and_seq_resend_table);  // common.p4#436 -> #220 -> #63
                    } else {
                        // 若为初次收到的梯度分片
                        // 若appID_and_Seq寄存器为空或则appID_and_Seq寄存器的值与p4ml.appIDandSeqNum相同
                        // 则将appID_and_Seq寄存器和mdata.isMyAppIDandMyCurrentSeq的值置为p4ml.appIDandSeqNum
                        apply(appID_and_seq_table); // common.p4#430 -> #216 -> #48
                    }
                    // Correct ID and Seq
                    if (mdata.isMyAppIDandMyCurrentSeq != 0) {
                        // 若该梯度包确实属于当前交换机正在处理的DT任务
                        if (p4ml.isResend == 1) {
                            // 将bitmap寄存器中的值放入mdata.bitmap中，并清零
                            apply(bitmap_resend_table); // commom.p4#304 -> #189 -> #37
                        } else {
                            // 若为正常的梯度分片，则将寄存器bitmap中该分片对应的分量置为1，并将更新后的值赋予mdata.bitmap
                            apply(bitmap_table); // common.p4#296 -> #185 -> #28
                        }

                        // 若mdata中已经记录发生了拥塞，则将寄存器ecn_register置为1
                        // 若交换机处已经记录出现拥塞，则将p4ml.ECN也置为1
                        apply(ecn_register_table); // common.p4#490 -> #259 -> #166
                        
                        // 将当前梯度分片的到达情况更新到mdata.integrated_bitmap中
                        apply(bitmap_aggregate_table);  // common.p4#313 -> #195

                        if (p4ml.isResend == 1) {
                            // Force forward and clean
                            apply(agtr_time_resend_table);
                        } else {
                            // 若可以进行聚合，则将agtr_time中的值加1,并更新到mdata.current_agtr_time中
                            apply(agtr_time_table); // common.p4#124
                        }

                        // bitmap correct
                        if (mdata.isAggregate != 0) {
                            if (mdata.current_agtr_time == p4ml.agtr_time) {
                                // 若寄存器register1中的值没有浮点溢出
                                // 则将p4ml_entries.data0累加到寄存器register1中，并更新到p4ml_entries.data0中
                                // tables.p4#41 -> actions.p4#13 -> registers.p4#282
                                apply(noequ0_processEntry1andWriteToPacket);    
                                apply(noequ0_processEntry2andWriteToPacket);
                                apply(noequ0_processEntry3andWriteToPacket);
                                apply(noequ0_processEntry4andWriteToPacket);
                                apply(noequ0_processEntry5andWriteToPacket);
                                apply(noequ0_processEntry6andWriteToPacket);
                                apply(noequ0_processEntry7andWriteToPacket);
                                apply(noequ0_processEntry8andWriteToPacket);
                                apply(noequ0_processEntry9andWriteToPacket);
                                apply(noequ0_processEntry10andWriteToPacket);
                                apply(noequ0_processEntry11andWriteToPacket);
                                apply(noequ0_processEntry12andWriteToPacket);
                                apply(noequ0_processEntry13andWriteToPacket);
                                apply(noequ0_processEntry14andWriteToPacket);
                                apply(noequ0_processEntry15andWriteToPacket);
                                apply(noequ0_processEntry16andWriteToPacket);
                                apply(noequ0_processEntry17andWriteToPacket);
                                apply(noequ0_processEntry18andWriteToPacket);
                                apply(noequ0_processEntry19andWriteToPacket);
                                apply(noequ0_processEntry20andWriteToPacket);
                                apply(noequ0_processEntry21andWriteToPacket);
                                apply(noequ0_processEntry22andWriteToPacket);
                                apply(noequ0_processEntry23andWriteToPacket);
                                apply(noequ0_processEntry24andWriteToPacket);
                                apply(noequ0_processEntry25andWriteToPacket);
                                apply(noequ0_processEntry26andWriteToPacket);
                                apply(noequ0_processEntry27andWriteToPacket);
                                apply(noequ0_processEntry28andWriteToPacket);
                                apply(noequ0_processEntry29andWriteToPacket);
                                apply(noequ0_processEntry30andWriteToPacket);
                                apply(noequ0_processEntry31andWriteToPacket);
                                //apply(noequ0_processEntry32andWriteToPacket);
                                // set output port
                                // if(ig_intr_md.resubmit_flag == 1) {
                                // 使用mdata.integrated_bitmap更新梯度分片中的p4ml.bitmap
                                apply(modify_packet_bitmap_table); // common.p4#455 -> #242
                                apply(outPort_table); //common.p4#349 具体逻辑未知，应是用于设置egress出端口
                                // } else {
                                    // apply(p4ml_resubmit);
                                // }
                            } else {
                                // 根据梯度分片是否是首次到达交换机选择处理逻辑
                                // 可根据表processEntry1的逻辑选择（1）将p4ml_entries.data0赋值给寄存器register1
                                // 或（2）将p4ml_entries.data0累加到寄存器register1中，并更新到p4ml_entries.data0中
                                // tables.p4#2 -> actions.p4#1 -> registers.p4#257
                                apply(processEntry1);
                                apply(processEntry2);
                                apply(processEntry3);
                                apply(processEntry4);
                                apply(processEntry5);
                                apply(processEntry6);
                                apply(processEntry7);
                                apply(processEntry8);
                                apply(processEntry9);
                                apply(processEntry10);
                                apply(processEntry11);
                                apply(processEntry12);
                                apply(processEntry13);
                                apply(processEntry14);
                                apply(processEntry15);
                                apply(processEntry16);
                                apply(processEntry17);
                                apply(processEntry18);
                                apply(processEntry19);
                                apply(processEntry20);
                                apply(processEntry21);
                                apply(processEntry22);
                                apply(processEntry23);
                                apply(processEntry24);
                                apply(processEntry25);
                                apply(processEntry26);
                                apply(processEntry27);
                                apply(processEntry28);
                                apply(processEntry29);
                                apply(processEntry30);
                                apply(processEntry31);
                                //apply(processEntry32);
                                
                                // 疑问：resubmit到底是什么？
                                if (ig_intr_md.resubmit_flag == 1) {
                                    apply(drop_table);
                                } else {
                                    apply(p4ml_resubmit);
                                }

                            }
                        } else {
                            if (mdata.current_agtr_time == p4ml.agtr_time) {
                                // 将register1中值读取到p4ml_entries.data0中
                                apply(Entry1WriteToPacket); // registers.p4#295
                                apply(Entry2WriteToPacket);
                                apply(Entry3WriteToPacket);
                                apply(Entry4WriteToPacket);
                                apply(Entry5WriteToPacket);
                                apply(Entry6WriteToPacket);
                                apply(Entry7WriteToPacket);
                                apply(Entry8WriteToPacket);
                                apply(Entry9WriteToPacket);
                                apply(Entry10WriteToPacket);
                                apply(Entry11WriteToPacket);
                                apply(Entry12WriteToPacket);
                                apply(Entry13WriteToPacket);
                                apply(Entry14WriteToPacket);
                                apply(Entry15WriteToPacket);
                                apply(Entry16WriteToPacket);
                                apply(Entry17WriteToPacket);
                                apply(Entry18WriteToPacket);
                                apply(Entry19WriteToPacket);
                                apply(Entry20WriteToPacket);
                                apply(Entry21WriteToPacket);
                                apply(Entry22WriteToPacket);
                                apply(Entry23WriteToPacket);
                                apply(Entry24WriteToPacket);
                                apply(Entry25WriteToPacket);
                                apply(Entry26WriteToPacket);
                                apply(Entry27WriteToPacket);
                                apply(Entry28WriteToPacket);
                                apply(Entry29WriteToPacket);
                                apply(Entry30WriteToPacket);
                                apply(Entry31WriteToPacket);
                                //apply(Entry32WriteToPacket);
                                // set output port
                                // if(ig_intr_md.resubmit_flag == 1) {
                                apply(modify_packet_bitmap_table);
                                apply(outPort_table);
                                // } else {
                                    // apply(p4ml_resubmit);
                                // }	
                            }
                        }
                    } else {
                        /* tag collision bit in incoming one */
                        // if not empty
                        if (p4ml.isResend == 0) {
                            apply(tag_collision_incoming_table);
                        }
                        apply(outPort_table);
                    }
                }
            }
    } else {
        // // BG traffic doesn't have data layer
        //   if (valid(p4ml_bg)){
        //      apply(bg_outPort_table);
        //   } else {
        apply(forward);
        //   }
    }
}

control egress 
{
      apply(qdepth_table);
      if (valid(ipv4)) {
          if (mdata.qdepth != 0) {
            apply(mark_ecn_ipv4_table);
          }
      }
      if (valid(p4ml_entries)) {
        if (mdata.qdepth != 0) {
            apply(modify_ecn_table);
        }
      }
}

