use core::ffi::c_void;

use crate::arraymap::{
    array_map_delete_elem, array_map_get_next_key, array_map_lookup_elem, array_map_update_elem,
    BpfArray,
};
use crate::bindings;
use crate::error::Error;

fn test_array(max_entries: u32) -> BpfArray {
    // SAFETY: bpf_map is an FFI layout type with no invalid all-zero bit pattern
    // for the fields used by array_map_get_next_key. Public fields are set below.
    let mut map: bindings::bpf_map = unsafe { core::mem::zeroed() };
    map.key_size = core::mem::size_of::<u32>() as u32;
    map.value_size = core::mem::size_of::<u64>() as u32;
    map.max_entries = max_entries;

    BpfArray {
        map,
        elem_size: core::mem::size_of::<u64>() as u32,
        index_mask: u32::MAX,
        value: core::ptr::null_mut(),
    }
}

#[test]
fn get_next_key_starts_at_zero_for_null_key() {
    let array = test_array(4);
    let mut next = u32::MAX;

    let result = unsafe {
        array_map_get_next_key(
            &array.map,
            core::ptr::null(),
            (&mut next as *mut u32).cast::<c_void>(),
        )
    };

    assert_eq!(result, Ok(()));
    assert_eq!(next, 0);
}

#[test]
fn get_next_key_advances_middle_index() {
    let array = test_array(4);
    let key = 1u32;
    let mut next = u32::MAX;

    let result = unsafe {
        array_map_get_next_key(
            &array.map,
            (&key as *const u32).cast::<c_void>(),
            (&mut next as *mut u32).cast::<c_void>(),
        )
    };

    assert_eq!(result, Ok(()));
    assert_eq!(next, 2);
}

#[test]
fn get_next_key_restarts_after_out_of_range_key() {
    let array = test_array(4);
    let key = 99u32;
    let mut next = u32::MAX;

    let result = unsafe {
        array_map_get_next_key(
            &array.map,
            (&key as *const u32).cast::<c_void>(),
            (&mut next as *mut u32).cast::<c_void>(),
        )
    };

    assert_eq!(result, Ok(()));
    assert_eq!(next, 0);
}

#[test]
fn get_next_key_reports_end_after_last_index() {
    let array = test_array(4);
    let key = 3u32;
    let mut next = u32::MAX;

    let result = unsafe {
        array_map_get_next_key(
            &array.map,
            (&key as *const u32).cast::<c_void>(),
            (&mut next as *mut u32).cast::<c_void>(),
        )
    };

    assert_eq!(result, Err(Error::ENOENT));
    assert_eq!(next, u32::MAX);
}

#[test]
fn update_then_lookup_round_trips_value() {
    let mut backing = [0u64; 4];
    let mut array = test_array(4);
    array.value = backing.as_mut_ptr().cast::<u8>();

    let key = 2u32;
    let written = 0xfeed_beef_dead_cafeu64;
    let update = unsafe {
        array_map_update_elem(
            &array.map,
            (&key as *const u32).cast::<c_void>(),
            (&written as *const u64).cast::<c_void>(),
            bindings::BPF_ANY,
        )
    };

    assert_eq!(update, Ok(()));
    assert_eq!(backing.get(2), Some(&written));

    let lookup =
        unsafe { array_map_lookup_elem(&array.map, (&key as *const u32).cast::<c_void>()) };
    let read_back = unsafe { core::ptr::read_unaligned(lookup.cast::<u64>()) };

    assert_eq!(read_back, written);
}

#[test]
fn lookup_returns_null_for_out_of_range_index() {
    let mut backing = [0u64; 4];
    let mut array = test_array(4);
    array.value = backing.as_mut_ptr().cast::<u8>();

    let key = 4u32;
    let lookup =
        unsafe { array_map_lookup_elem(&array.map, (&key as *const u32).cast::<c_void>()) };

    assert!(lookup.is_null());
    assert_eq!(backing, [0; 4]);
}

#[test]
fn update_rejects_out_of_range_index() {
    let mut backing = [0u64; 4];
    let mut array = test_array(4);
    array.value = backing.as_mut_ptr().cast::<u8>();

    let key = 4u32;
    let value = 7u64;
    let result = unsafe {
        array_map_update_elem(
            &array.map,
            (&key as *const u32).cast::<c_void>(),
            (&value as *const u64).cast::<c_void>(),
            bindings::BPF_ANY,
        )
    };

    assert_eq!(result, Err(Error::E2BIG));
    assert_eq!(backing, [0; 4]);
}

#[test]
fn update_rejects_noexist_because_array_slots_always_exist() {
    let mut backing = [0u64; 4];
    let mut array = test_array(4);
    array.value = backing.as_mut_ptr().cast::<u8>();

    let key = 1u32;
    let value = 7u64;
    let result = unsafe {
        array_map_update_elem(
            &array.map,
            (&key as *const u32).cast::<c_void>(),
            (&value as *const u64).cast::<c_void>(),
            bindings::BPF_NOEXIST,
        )
    };

    assert_eq!(result, Err(Error::EEXIST));
    assert_eq!(backing, [0; 4]);
}

#[test]
fn delete_is_not_supported_for_array_maps() {
    let array = test_array(4);
    let key = 1u32;

    let result =
        unsafe { array_map_delete_elem(&array.map, (&key as *const u32).cast::<c_void>()) };

    assert_eq!(result, Err(Error::EINVAL));
}
