// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Policy hot-reload consumer for Post (design ).
//!
//! Thin re-export of the shared runtime consumer (`sentin8::shield::runtime`) —
//! every adopting service uses the same poll/ACK/reload loop.
