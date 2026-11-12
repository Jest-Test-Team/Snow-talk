//! Calibrate difficulty: run on a mid-range phone target, aim for 2–3 s.
use criterion::{criterion_group, criterion_main, Criterion};
use snow_pow::Challenge;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("pow");
    g.sample_size(10);
    for d in [16u8, 18, 20] {
        let ch = Challenge::issue(b"k", 0, d, [d; 16]);
        g.bench_function(format!("solve_d{d}"), |b| b.iter(|| ch.solve()));
    }
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
