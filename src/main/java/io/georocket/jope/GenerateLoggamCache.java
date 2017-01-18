package io.georocket.jope;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.IntStream;

/**
 * Generate values for {@link Hgd#loggamCache} by iterating over all input
 * values in the range of [0, 2^29]. The cache values are written to
 * {@link System#out}, log messages are written to {@link System#err}
 * @author Michel Kraemer
 */
public class GenerateLoggamCache {
	public static void main(String[] args) {
		String key = "S0M3 $TR@NG Key";
		OPE o = new OPE(key, 32, 48);
		
		long start = System.currentTimeMillis();
//		for (int i = 23864313; i < 23864314 + 1; i++) {
		AtomicLong count = new AtomicLong(0L);
		IntStream.rangeClosed(0, 536870912).parallel().forEach(i -> {
			long n = count.getAndIncrement();
			BigInteger p = BigInteger.valueOf(i);
			BigInteger e = o.encrypt(p);
//			BigInteger d = o.decrypt(e);
//
//			if (d.compareTo(p) != 0)
//				throw new RuntimeException("failed: " + p + " " + d);

			if (n % 10000 == 0) {
				System.err.println(n);
				System.err.println("CACHE: " + o.cache.size());
				System.err.println("CACHE HITS: " + o.cacheHits);
				System.err.println("LOG CACHE: " + o.hgd.loggamCache.size());
				System.err.println("LOG HITS: " + o.hgd.loggamHits);
			}
			
			if (n % 1000000 == 0) {
				o.clearCache();
			}
		});
		
		long end = System.currentTimeMillis();
		System.err.println("TIME: " + (end - start));
		System.err.println("CACHE: " + o.cache.size());
		System.err.println("CACHE HITS: " + o.cacheHits);
		System.err.println("LOG CACHE: " + o.hgd.loggamCache.size());
		System.err.println("LOG HITS: " + o.hgd.loggamHits);
		
		List<LogGamHit> loggamhitlist = new ArrayList<>();
		for (Entry<BigDecimal, BigInteger> e : o.hgd.loggamCacheHitCount.entrySet()) {
			loggamhitlist.add(new LogGamHit(e.getKey(), o.hgd.loggamCache.get(e.getKey()), e.getValue()));
		}
		for (int i = 0; i < loggamhitlist.size(); ++i) {
			System.out.println(loggamhitlist.get(i).d + " " + loggamhitlist.get(i).v
					/* + " " + loggamhitlist.get(i).count*/);
		}
	}
	
	private static class LogGamHit {
		final BigDecimal d;
		final BigDecimal v;
		final BigInteger count;
		
		LogGamHit(BigDecimal d, BigDecimal v, BigInteger count) {
			this.d = d;
			this.v = v;
			this.count = count;
		}
	}
}
