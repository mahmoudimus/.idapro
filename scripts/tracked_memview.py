import builtins
import ctypes

orignal_memoryview = builtins.memoryview


class TrackedMemoryView:
    def __init__(self, data, rcb, wcb):
        self.mv = orignal_memoryview(data)
        self.rcb, self.wcb = rcb, wcb

    def __getitem__(self, index):
        self.rcb(self.mv, index)
        return self.mv[index]

    def __setitem__(self, index, value):
        self.mv[index] = value
        self.wcb(self.mv, index)

    def cast(self, new_type, **kwargs):
        self.mv = self.mv.cast(new_type, **kwargs)
        return self

    @property
    def nbytes(self):
        return self.mv.nbytes

    def __len__(self):
        return len(self.mv)

    def __repr__(self):
        return repr(self.mv)
