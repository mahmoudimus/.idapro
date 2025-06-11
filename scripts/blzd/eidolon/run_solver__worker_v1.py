    def worker():
        print(f"[+] worker started")
        prev_state = read_state(tc, state_kind, state_desc)
        G.add_node(prev_state)
        steps = 0

        for idx, ip in enumerate(idautils.Heads(FUNC_EA)):
            # print(f"[+] ip: 0x{ip:X} - {idx}")
            if idx > MAX_STEPS:
                break
            tc.setConcreteRegisterValue(tc.registers.rip, ip)
            ensure_mapped(tc, ip)
            # -- hard stop: left function -----------------------------
            if not within_function(ip):
                print(f"[!] left function at 0x{ip:X}")
                break
            size = idc.get_item_size(ip)
            mnem = idc.print_insn_mnem(ip)

            # print(f"[+] ip: 0x{ip:X} - {mnem} - (size: {size})")
            # 1) Detect helper CALLs early
            # if mnem == "call":
            #     callee = idc.print_operand(ip, 0)
            #     if callee:

            #         # ––– STUB –––
            #         rsp = tc.getConcreteRegisterValue(tc.registers.rsp) - 8
            #         tc.setConcreteRegisterValue(tc.registers.rsp, rsp)
            #         tc.setConcreteMemoryAreaValue(rsp, struct.pack("<Q", ip + size))
            #         tc.setConcreteRegisterValue(tc.registers.rax, 0)
            #         print(f"[+] callee:  - stubbed to 0x{ip + size:X} @0x{ip:X}")
            #         continue  # skip tc.processing()
            # elif mnem == "nop":
            #     print(f"[+] nop @0x{ip:X}")
            #     continue

            # -- single-step ------------------------------------------
            try:
                instr = Instruction()
                instr.setOpcode(ida_bytes.get_bytes(ip, size))  # max
                instr.setAddress(ip)
                tc.processing(instr)
            except Exception as e:
                print(f"[!] Triton error @0x{ip:X}: {e}")
                break

            steps += 1

            # -- early stop on RET/JMP --------------------------------
            if is_ret(ip):
                ret_addr = tc.getConcreteMemoryValue(
                    tc.getConcreteRegisterValue(tc.registers.rsp)
                )
                if not within_function(ret_addr):
                    print(f"[!] early stop on RET @0x{ip:X} to 0x{ret_addr:X}")
                    break

            if is_uncond_jmp_reg(ip):
                addr = idc.get_operand_value(ip, 0)
                if not within_function(addr):
                    print(f"[!] early stop on JMP @0x{ip:X} to 0x{addr:X}")
                    break

            # -- record state change ----------------------------------
            cur_state = read_state(tc, state_kind, state_desc)
            if steps % 1000 == 0:
                print(
                    f"[+] 0x{ip:X} - cur_state: {cur_state}, prev_state: {prev_state}"
                )
            if cur_state != prev_state:
                # Add the nodes and the directed edge to our graph
                if not G.has_node(cur_state):
                    print(f"[+] Discovered new state: {cur_state}")

                G.add_node(prev_state)
                G.add_node(cur_state)
                G.add_edge(prev_state, cur_state, ip=ip)

                print(
                    f"[+] Graph edge: {prev_state} -> {cur_state} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)"
                )
                prev_state = cur_state

            # --- Intelligent Stop Condition ---
            # If we've found all expected states AND we have returned to a node
            # whose successors we have already explored, we are likely done.
            if G.number_of_nodes() >= si.ncases:
                if G.has_node(cur_state) and G.out_degree(cur_state) > 0:
                    print(
                        f"[+] All {si.ncases} states discovered and returned to a known path. Stopping."
                    )
                    break
                # if cur_state != prev_state:
                #     edges.add(Edge(prev_state, cur_state, ip))
                #     prev_state = cur_state
                # visited.add(cur_state)
                # if len(visited) == si.ncases:
                #     if cur_state == 0:
                #         print(f"[!] visited all {si.ncases} cases")
                #         break
                # print(f"[+] visited {len(edges)} edges in {steps} steps")
        print(
            f"[+] Solver finished. Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges in {steps} steps."
        )