import pytest
import ctypes
from unittest.mock import patch, MagicMock


# Simulated buffer management module mimicking the vulnerable pattern
class Buffer:
    def __init__(self, size=0):
        self.ptr = None
        self.size = size
        self._refs = []
        if size > 0:
            self.ptr = bytearray(size)
            self._refs.append(id(self.ptr))

    def safe_realloc(self, new_size):
        """Safe realloc: preserves original ptr on failure"""
        if new_size <= 0:
            raise ValueError("Invalid size")
        old_ptr = self.ptr
        try:
            new_ptr = bytearray(new_size)
            if old_ptr:
                copy_size = min(len(old_ptr), new_size)
                new_ptr[:copy_size] = old_ptr[:copy_size]
            self.ptr = new_ptr
            self.size = new_size
            return True
        except MemoryError:
            # SAFE: original ptr is preserved on failure
            return False

    def unsafe_realloc(self, new_size):
        """Unsafe realloc: mimics the vulnerable pattern (overwrites ptr with None on failure)"""
        if new_size <= 0:
            raise ValueError("Invalid size")
        old_ptr = self.ptr
        try:
            new_ptr = bytearray(new_size)
            if old_ptr:
                copy_size = min(len(old_ptr), new_size)
                new_ptr[:copy_size] = old_ptr[:copy_size]
            self.ptr = new_ptr
            self.size = new_size
            return True
        except MemoryError:
            # VULNERABLE: overwrites ptr with None, losing reference to original
            self.ptr = None  # This is the bug: use-after-free / null deref
            return False


def simulate_krealloc(buf, new_size, fail=False):
    """
    Simulates krealloc behavior.
    Returns (new_ptr, success).
    Safe pattern: only assign if not None.
    """
    if fail:
        return None, False
    try:
        new_ptr = bytearray(new_size)
        if buf.ptr:
            copy_size = min(len(buf.ptr), new_size)
            new_ptr[:copy_size] = buf.ptr[:copy_size]
        return new_ptr, True
    except (MemoryError, OverflowError):
        return None, False


@pytest.mark.parametrize("payload", [
    # (initial_size, new_size, should_fail, description)
    (0, 0, True, "zero_to_zero"),
    (1, 0, True, "shrink_to_zero"),
    (4096, 2**63 - 1, True, "overflow_size"),
    (4096, -1, True, "negative_size"),
    (4096, 2**32, True, "huge_allocation"),
    (0, 4096, False, "null_to_valid"),
    (4096, 8192, False, "normal_grow"),
    (8192, 4096, False, "normal_shrink"),
    (1, 1, False, "same_size"),
    (4096, 4097, False, "grow_by_one"),
    (4096, 4095, False, "shrink_by_one"),
    (0, 1, False, "zero_to_one"),
    (2**16, 2**16, False, "large_same_size"),
    (4096, 2**31, True, "near_overflow"),
    (1024, 2**20, False, "large_grow"),
])
def test_realloc_security_invariant(payload):
    """
    Invariant: After a realloc operation (whether successful or failed),
    buf->ptr must NEVER be set to NULL/None if the original pointer was valid
    and the allocation failed. The original pointer must remain accessible
    and valid to prevent use-after-free and NULL pointer dereference vulnerabilities.
    """
    initial_size, new_size, should_fail, description = payload

    # Setup buffer with initial allocation
    buf = Buffer()
    if initial_size > 0:
        try:
            buf.ptr = bytearray(initial_size)
            buf.size = initial_size
        except (MemoryError, OverflowError):
            pytest.skip(f"Cannot allocate initial buffer of size {initial_size}")

    original_ptr = buf.ptr
    had_valid_ptr = buf.ptr is not None

    # Simulate krealloc with potential failure
    try:
        new_ptr, success = simulate_krealloc(buf, new_size, fail=should_fail)
    except (ValueError, OverflowError, TypeError):
        new_ptr, success = None, False

    # SECURITY INVARIANT: Safe assignment pattern
    # Only update buf.ptr if krealloc succeeded (returned non-None)
    if new_ptr is not None:
        buf.ptr = new_ptr
        buf.size = new_size
        # After successful realloc, ptr must be valid
        assert buf.ptr is not None, (
            f"[{description}] buf.ptr must not be None after successful realloc"
        )
        assert len(buf.ptr) == new_size, (
            f"[{description}] buf.ptr size mismatch after realloc"
        )
    else:
        # CRITICAL INVARIANT: On failure, original ptr must be preserved
        # Do NOT assign None to buf.ptr (the vulnerable pattern)
        # buf.ptr remains unchanged (original_ptr)
        pass  # Safe: we don't touch buf.ptr

    # INVARIANT 1: If original ptr was valid and realloc failed,
    # buf.ptr must still point to the original valid memory
    if had_valid_ptr and not success:
        assert buf.ptr is not None, (
            f"[{description}] SECURITY VIOLATION: buf.ptr was set to None after failed realloc. "
            f"Original valid pointer lost — potential use-after-free or NULL dereference. "
            f"initial_size={initial_size}, new_size={new_size}"
        )
        assert buf.ptr is original_ptr, (
            f"[{description}] SECURITY VIOLATION: buf.ptr changed after failed realloc. "
            f"Original pointer must be preserved to prevent memory corruption."
        )

    # INVARIANT 2: If realloc succeeded, ptr must be valid and accessible
    if success and new_ptr is not None:
        assert buf.ptr is not None, (
            f"[{description}] buf.ptr must be valid after successful realloc"
        )
        # Verify the memory is accessible (no use-after-free)
        try:
            _ = buf.ptr[0] if len(buf.ptr) > 0 else None
        except (IndexError, TypeError) as e:
            pytest.fail(
                f"[{description}] Memory access violation after realloc: {e}"
            )

    # INVARIANT 3: Buffer state consistency — size and ptr must be coherent
    if buf.ptr is not None:
        assert buf.size == len(buf.ptr), (
            f"[{description}] Buffer size inconsistency: "
            f"buf.size={buf.size} but len(buf.ptr)={len(buf.ptr)}"
        )
    else:
        # ptr is None only if it was None originally (never had valid allocation)
        assert not had_valid_ptr, (
            f"[{description}] SECURITY VIOLATION: Valid pointer was lost. "
            f"This indicates the dangerous krealloc pattern was used."
        )


@pytest.mark.parametrize("sizes", [
    (4096, [8192, 16384, 4096, 2048, 4096]),
    (1024, [2048, 4096, 8192, 16384, 32768]),
    (512, [256, 128, 64, 32, 16]),
    (4096, [4096, 4096, 4096, 4096]),
])
def test_sequential_realloc_invariant(sizes):
    """
    Invariant: Sequential realloc operations must never result in a NULL/None
    pointer when previous allocations were valid. Each realloc must either
    succeed with a valid pointer or preserve the original pointer on failure.
    """
    initial_size, new_sizes = sizes

    buf = Buffer()
    buf.ptr = bytearray(initial_size)
    buf.size = initial_size

    for step, new_size in enumerate(new_sizes):
        old_ptr = buf.ptr
        old_size = buf.size
        had_valid = buf.ptr is not None

        new_ptr, success = simulate_krealloc(buf, new_size, fail=False)

        if new_ptr is not None:
            buf.ptr = new_ptr
            buf.size = new_size
        # else: preserve original (safe pattern)

        # After each step, if we had a valid pointer, we must still have one
        if had_valid:
            assert buf.ptr is not None, (
                f"Step {step}: SECURITY VIOLATION — valid pointer lost during sequential realloc. "
                f"old_size={old_size}, new_size={new_size}"
            )

        # Memory must be accessible
        if buf.ptr is not None and len(buf.ptr) > 0:
            try:
                buf.ptr[0] = 0xAA
                assert buf.ptr[0] == 0xAA
            except (IndexError, TypeError) as e:
                pytest.fail(f"Step {step}: Memory access violation: {e}")


def test_null_ptr_not_dereferenced_after_failed_realloc():
    """
    Invariant: A NULL/None pointer must never be dereferenced after a failed
    realloc. The safe pattern requires checking the return value before
    assigning to buf->ptr.
    """
    buf = Buffer()
    buf.ptr = bytearray(4096)
    buf.size = 4096
    original_data = bytearray(buf.ptr)

    # Simulate failed krealloc
    new_ptr, success = simulate_krealloc(buf, 2**63 - 1, fail=True)

    assert new_ptr is None, "Expected krealloc to fail"
    assert not success, "Expected krealloc to fail"

    # SAFE PATTERN: Only assign if not None
    if new_ptr is not None:
        buf.ptr = new_ptr  # This line should NOT execute
        pytest.fail("Should not reach here — krealloc returned None")

    # INVARIANT: Original pointer must still be valid
    assert buf.ptr is not None, (
        "SECURITY VIOLATION: buf.ptr is None after failed realloc. "
        "This is the dangerous pattern: buf->ptr = krealloc(...) when krealloc returns NULL"
    )

    # INVARIANT: Original data must be intact
    assert buf.ptr == original_data, (
        "SECURITY VIOLATION: Original data corrupted after failed realloc"
    )

    # INVARIANT: Memory must be accessible without crash
    try:
        _ = buf.ptr[0]
        _ = buf.ptr[-1]
        _ = len(buf.ptr)
    except (TypeError, IndexError) as e:
        pytest.fail(f"NULL pointer dereference after failed realloc: {e}")