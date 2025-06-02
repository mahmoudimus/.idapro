import idaapi
import idautils
from mutilz.actions.force_analyze import ForceAnalyzeActionHandler
from mutilz.helpers.ida import ida_tguidm

text_seg = idaapi.get_segm_by_name(".text")
functions = idautils.Functions(text_seg.start_ea, text_seg.end_ea)
for function_ea in ida_tguidm(functions):
    ForceAnalyzeActionHandler.reanalyze_function(function_ea)
