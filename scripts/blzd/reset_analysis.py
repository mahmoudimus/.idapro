import ida_auto
import ida_ida

start = ida_ida.inf_get_min_ea()
end = ida_ida.inf_get_max_ea()
ida_auto.revert_ida_decisions(start, end)
ida_auto.plan_and_wait(start, end)
