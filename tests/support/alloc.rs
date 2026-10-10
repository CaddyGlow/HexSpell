use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static COUNTS: Cell<(bool, usize, usize)> = const { Cell::new((false, 0, 0)) };
}

pub struct CountingAllocator;

fn record(size: usize) {
    let _ = COUNTS.try_with(|counts| {
        let (enabled, count, bytes) = counts.get();
        if enabled {
            counts.set((true, count + 1, bytes + size));
        }
    });
}

// SAFETY: Every operation delegates to System with the original pointer and layout.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

/// Counts allocation/reallocation calls and requested bytes on this thread.
pub fn measured<T>(action: impl FnOnce() -> T) -> (T, usize, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = COUNTS.try_with(|counts| {
                let (_, count, bytes) = counts.get();
                counts.set((false, count, bytes));
            });
        }
    }
    COUNTS.with(|counts| counts.set((true, 0, 0)));
    let reset = Reset;
    let output = action();
    drop(reset);
    let (_, count, bytes) = COUNTS.with(Cell::get);
    (output, count, bytes)
}
