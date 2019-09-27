#![feature(unwind_attributes)]

use lucet_runtime_tests::strcmp_tests;

strcmp_tests!(lucet_runtime::MmapRegion);
