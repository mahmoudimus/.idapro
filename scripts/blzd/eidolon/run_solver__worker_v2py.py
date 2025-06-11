    def worker():
        print(f"[+] worker started")
        prev_state = read_state(tc, state_kind, state_desc)
        G.add_node(prev_state)
        steps = 0

        # Get the initial instruction pointer from the context
        ip = tc.getConcreteRegisterValue(tc.registers.rip)

        while within_function(ip) and steps < MAX_STEPS:
            print(f"[+] ip: 0x{ip:X} - {steps}")
            # Ensure the memory for the current instruction is mapped
            ensure_mapped(tc, ip)

            # Get instruction bytes
            try:
                size = idaapi.get_item_size(ip)
                if not size:
                    print(f"[!] Could not get instruction size at 0x{ip:X}. Stopping.")
                    break
                opcode = ida_bytes.get_bytes(ip, size)
                if not opcode:
                    print(
                        f"[!] Could not read instruction bytes at 0x{ip:X}. Stopping."
                    )
                    break
            except Exception as e:
                print(f"[!] Error reading instruction at 0x{ip:X}: {e}")
                break

            # Create and process the instruction
            instr = Instruction()
            instr.setAddress(ip)
            instr.setOpcode(opcode)

            try:
                tc.processing(instr)
            except Exception as e:
                print(f"[!] Triton exception at 0x{ip:X}: {e}")
                traceback.print_exc()
                break

            steps += 1

            # -- record state change ----------------------------------
            cur_state = read_state(tc, state_kind, state_desc)
            if steps % 1000 == 0:
                print(
                    f"[+] 0x{ip:X} - cur_state: {cur_state}, prev_state: {prev_state}"
                )
            if cur_state != prev_state:
                if not G.has_node(cur_state):
                    print(f"[+] Discovered new state: {cur_state}")

                G.add_node(prev_state)
                G.add_node(cur_state)
                G.add_edge(prev_state, cur_state, ip=ip)

                print(
                    f"[+] State transition: {prev_state} -> {cur_state} at 0x{ip:X} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)"
                )
                prev_state = cur_state

            # --- Intelligent Stop Condition ---
            if G.number_of_nodes() >= si.ncases:
                if G.has_node(cur_state) and G.out_degree(cur_state) > 0:
                    print(
                        f"[+] All {si.ncases} states discovered and returned to a known path. Stopping."
                    )
                    break

            # Update ip for the next iteration FROM THE EMULATOR STATE
            ip = tc.getConcreteRegisterValue(tc.registers.rip)