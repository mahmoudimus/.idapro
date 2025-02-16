import typing
import idaapi
import idautils
import idc
import ida_ua
import ida_bytes
import ida_segment
import ida_allins
import ida_kernwin


class Comparable(object):
    _comparable: typing.ClassVar
    
    """Assumes child has self._comparable attr/@property"""

    def __lt__(self, other):
        return self._comparable < other._comparable

    def __le__(self, other):
        return (self < other) or (self == other)

    def __eq__(self, other):
        return self._comparable == other._comparable

    def __ne__(self, other):
        return not self == other

    def __gt__(self, other):
        return not self <= other

    def __ge__(self, other):
        return not self < other


class ida_tguidm:

    def __init__(self, iterable, total=None, initial=0):
        self.iterable = iterable

        if total is None and iterable is not None:
            try:
                total = len(iterable)
            except (TypeError, AttributeError):
                total = None

        if total == float("inf"):
            # Infinite iterations, behave same as unknown
            total = None
        self.total = total            
        self.n = initial

    def __iter__(self):
        return self

    def __next__(self):
        # Inlining instance variables as locals (speed optimization)
        iterable = self.iterable
        total = self.total
        ida_kernwin.show_wait_box(f'Executing...')
        for idx, item in enumerate(iterable, start=1):
            # did the user cancel?
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()
                ida_kernwin.warning('Canceled')
                raise StopIteration
            ida_kernwin.replace_wait_box(f'Processing ({idx}/{total})')
            try:
                yield item                
            except Exception as e:
                ida_kernwin.warning(f"Unexpected error {e}")
                break

        ida_kernwin.hide_wait_box()
        # try:
        #     name = ida_funcs.get_func_name(function.start_ea)
        #     entities = YaraExtractor(FunctionExtractor(function.start_ea))
        #     rule = generate_rule(name=name, entities=list(entities))
        #     if not rule.is_empty():
        #         ruleset.append(rule)
        # except Exception as e:
        #     ida_kernwin.warning(f'Yarka - unexpected error {e}')


class Deflow():
    
   # Buffer is a copy of the .text section
    # Function to deflow the given buffer and functions
    def deflow(self, textsec, functions: list[Addr]):
        breakpoint()
        for func in ida_tguidm(functions):
            newDiscovered = 0
            chunks = self.deflow_chunk(textsec, func)
            # print("[+] deflowed chunks: ", len(chunks))
            while len(chunks) != 0:
                newChunks = []
                for c in chunks:
                    newChunks.extend(self.deflow_chunk(textsec, c))
                newDiscovered += len(chunks)
                chunks = newChunks

if __name__ == "__main__":
    # Get the .text section of the loaded binary
    textsec = idaapi.get_segm_by_name(".text")
    # Get the list of function addresses in the .text section
    functions = list(map(Addr, idautils.Functions(textsec.start_ea, textsec.end_ea)))
    # Initialize and run the Deflow algorithm
    deflow = Deflow()
    # deflow.deflow(textsec, functions[:4])
    deflow.deflow(textsec, functions)
