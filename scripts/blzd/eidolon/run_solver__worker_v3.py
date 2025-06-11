    def worker():
        print("[+] Worker started with call-aware emulation loop.")
        
        # We only care about state changes that happen *inside* the target function.
        # Initialize prev_state when we are inside.
        prev_state = read_state(tc, state_kind, state_desc)
        G.add_node(prev_state)
        
        steps = 0
        call_depth = 0 # Start at depth 0, in the main function.

        ip = tc.getConcreteRegisterValue(tc.registers.rip)

        while steps < MAX_STEPS:
            # Stop condition: if we return from the initial function call.
            if call_depth < 0:
                print(f"[+] Emulation returned from initial function at 0x{ip:X}. Stopping.")
                break

            # Ensure memory is mapped for the current instruction
            ensure_mapped(tc, ip)
            
            try:
                size = idaapi.get_item_size(ip)
                if not size:
                    print(f"[!] Could not get instruction size at 0x{ip:X}. Stopping.")
                    break
                opcode = ida_bytes.get_bytes(ip, size)
                if not opcode:
                    print(f"[!] Could not read instruction bytes at 0x{ip:X}. Stopping.")
                    break
            except Exception as e:
                print(f"[!] Error reading instruction at 0x{ip:X}: {e}")
                break

            # Create and process the instruction
            instr = Instruction()
            instr.setAddress(ip)
            instr.setOpcode(opcode)
            
            # Track call depth
            if instr.isControlFlow():
                mnem = instr.getDisassembly().split()[0]
                if mnem == 'call':
                    call_depth += 1
                elif mnem == 'ret':
                    call_depth -= 1

            try:
                if not tc.processing(instr):
                    print(f"[!] Triton failed to process instruction at 0x{ip:X}: {instr.getDisassembly()}")
                    break
            except Exception as e:
                print(f"[!] Triton exception at 0x{ip:X}: {e}")
                traceback.print_exc()
                break

            steps += 1
            
            # Get the next instruction pointer from the emulator
            next_ip = tc.getConcreteRegisterValue(tc.registers.rip)

            # --- STATE CHANGE RECORDING ---
            # We only care about state transitions that are committed *inside* the target function.
            if within_target_function(ip):
                cur_state = read_state(tc, state_kind, state_desc)
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
            
            # Update ip for the next iteration
            ip = next_ip

        print(
            f"[+] Solver finished. Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges in {steps} steps."
        )