// NSFW detection temporarily disabled due to dependency conflict
// between nsfw crate (requires time v0.3.23 via tract) and matrix-sdk (requires time >= 0.3.42)
//
// TODO: Re-enable when either:
// 1. nsfw crate is updated to use newer tract
// 2. We find an alternative NSFW detection library
// 3. We remove matrix-sdk dependency

// TODO: Add alt text generation for accessibility
//
// Future implementation:
// #[cfg(feature = "image-captioning")]
// pub fn generate_alt_text(img: &DynamicImage) -> Result<String> {
//     use candle_transformers::models::blip;
//     // Load BLIP-2 model
//     // Generate caption from image
//     // Return: "a person standing in front of a building"
// }
//
// Add to Cargo.toml:
// candle-core = { version = "0.3", optional = true }
// candle-transformers = { version = "0.3", optional = true }
//
// [features]
// image-captioning = ["candle-core", "candle-transformers"]
