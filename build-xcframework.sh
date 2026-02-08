#!/usr/bin/env bash
set -euo pipefail

CRATE_NAME="c2pa_opentdf"
LIB_NAME="lib${CRATE_NAME}.a"
FRAMEWORK_NAME="C2paOpenTDF"
TARGET_DIR="target"
XCFRAMEWORK_DIR="${TARGET_DIR}/${FRAMEWORK_NAME}.xcframework"

TARGETS=(
    "aarch64-apple-darwin"
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
)

echo "==> Checking prerequisites..."
if ! command -v xcodebuild &>/dev/null; then
    echo "ERROR: xcodebuild not found. Install Xcode and its command-line tools."
    exit 1
fi

echo "==> Checking required Rust targets..."
for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "^${target}$"; then
        echo "    Adding target: ${target}"
        rustup target add "${target}"
    fi
done

echo "==> Building static libraries..."
for target in "${TARGETS[@]}"; do
    echo "    Building for ${target}..."
    cargo build --release --target "${target}"
done

echo "==> Generating C header..."
cargo build 2>/dev/null || true
HEADER="include/c2pa_opentdf.h"
if [ ! -f "${HEADER}" ]; then
    echo "ERROR: Header not generated at ${HEADER}"
    exit 1
fi

echo "==> Preparing XCFramework slices..."
rm -rf "${XCFRAMEWORK_DIR}"

# Create per-platform directories with headers and modulemap
for target in "${TARGETS[@]}"; do
    SLICE_DIR="${TARGET_DIR}/xcf-staging/${target}"
    mkdir -p "${SLICE_DIR}/Headers"

    cp "${TARGET_DIR}/${target}/release/${LIB_NAME}" "${SLICE_DIR}/"
    cp "${HEADER}" "${SLICE_DIR}/Headers/"

    cat > "${SLICE_DIR}/Headers/module.modulemap" <<EOF
module ${FRAMEWORK_NAME} {
    header "c2pa_opentdf.h"
    export *
}
EOF
done

echo "==> Creating XCFramework..."
XCODEBUILD_ARGS=()
for target in "${TARGETS[@]}"; do
    SLICE_DIR="${TARGET_DIR}/xcf-staging/${target}"
    XCODEBUILD_ARGS+=(-library "${SLICE_DIR}/${LIB_NAME}" -headers "${SLICE_DIR}/Headers")
done

xcodebuild -create-xcframework \
    "${XCODEBUILD_ARGS[@]}" \
    -output "${XCFRAMEWORK_DIR}"

echo "==> Cleaning up staging..."
rm -rf "${TARGET_DIR}/xcf-staging"

echo ""
echo "Done! XCFramework created at:"
echo "  ${XCFRAMEWORK_DIR}"
echo ""
echo "Slices:"
for target in "${TARGETS[@]}"; do
    SIZE=$(du -sh "${TARGET_DIR}/${target}/release/${LIB_NAME}" | cut -f1)
    echo "  ${target}: ${SIZE}"
done
