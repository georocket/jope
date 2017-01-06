package io.georocket.jope;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class OPE {

	final static int PRECISION = 20;
	final static RoundingMode RM = RoundingMode.HALF_UP;

	final String key;
	final ValueRange inRange;
	final ValueRange outRange;
	
	final Map<BigInteger, BigInteger> cache = new ConcurrentHashMap<>();
	final Map<BigInteger, BigInteger> cacheHitCount = new ConcurrentHashMap<>();
	final AtomicLong cacheHits = new AtomicLong(0L);
	
	final Hgd hgd = new Hgd();

	public OPE(String key) {
		this(key, 32, 48);
	}
	
	public OPE(String key, int inBits, int outBits) {
		this(key, new ValueRange(new BigInteger("2").pow(inBits).negate(),
						new BigInteger("2").pow(inBits)),
				new ValueRange(new BigInteger("2").pow(outBits).negate(),
						new BigInteger("2").pow(outBits)));
	}
	
	public OPE(String key, ValueRange inRange, ValueRange outRange) {
		this.key = key;
		this.inRange = inRange;
		this.outRange = outRange;
	}
	
	public void clearCache() {
		cache.clear();
		cacheHitCount.clear();
	}

	public BigInteger encrypt(BigInteger ptxt) {

		if (!this.inRange.contains(ptxt))
			throw new RuntimeException("Plaintext is not within the input range");

		return this.encryptRecursive(ptxt, this.inRange, this.outRange);
	}

	private BigInteger encryptRecursive(BigInteger ptxt, ValueRange inRange, ValueRange outRange) {

		BigInteger inSize = inRange.size();
		BigInteger outSize = outRange.size();

		if (inRange.size().compareTo(BigInteger.ONE) == 0) {
			Coins coins = new Coins(this.key, ptxt);
			return sampleUniform(outRange, coins);
		}

		BigInteger inEdge = inRange.start.subtract(BigInteger.ONE);
		BigInteger outEdge = outRange.start.subtract(BigInteger.ONE);

		BigDecimal two = new BigDecimal("2");
		BigInteger m = new BigDecimal(outSize).divide(two, PRECISION, RoundingMode.CEILING)
				.toBigInteger();
		BigInteger mid = outEdge.add(m);

		BigInteger cacheKey = outRange.start.add(m);
		final ValueRange finalInRange = inRange;
		final ValueRange finalOutRange = outRange;
		BigInteger x = cache.compute(cacheKey, (k, v) -> {
			if (v == null) {
				Coins coins = new Coins(this.key, mid);
				return sampleHGD(finalInRange, finalOutRange, mid, coins);
			} else {
				cacheHitCount.merge(k, BigInteger.ONE, (a, b) -> a.add(b));
				cacheHits.incrementAndGet();
				return v;
			}
		});

		if (ptxt.compareTo(x) <= 0) {
			inRange = new ValueRange(inEdge.add(BigInteger.ONE), x);
			outRange = new ValueRange(outEdge.add(BigInteger.ONE), mid);
		} else {
			inRange = new ValueRange(x.add(BigInteger.ONE), inEdge.add(inSize));
			outRange = new ValueRange(mid.add(BigInteger.ONE), outEdge.add(outSize));
		}

		return this.encryptRecursive(ptxt, inRange, outRange);
	}

	public BigInteger decrypt(BigInteger ctxt) {

		if (!this.outRange.contains(ctxt))
			throw new RuntimeException("Ciphertext is not within the input range");

		return this.decryptRecursive(ctxt, this.inRange, this.outRange);
	}

	private BigInteger decryptRecursive(BigInteger ctxt, ValueRange inRange, ValueRange outRange) {

		BigInteger inSize = inRange.size();
		BigInteger outSize = outRange.size();

		if (inRange.size().compareTo(BigInteger.ONE) == 0) {
			BigInteger inRangeMin = inRange.start;
			Coins coins = new Coins(this.key, inRangeMin);
			BigInteger sampledCtxt = sampleUniform(outRange, coins);

			if (sampledCtxt.compareTo(ctxt) == 0)
				return inRangeMin;
			else
				throw new RuntimeException("Invalid ciphertext");

		}

		BigInteger inEdge = inRange.start.subtract(BigInteger.ONE);
		BigInteger outEdge = outRange.start.subtract(BigInteger.ONE);
		BigDecimal two = new BigDecimal("2");
		BigInteger m = new BigDecimal(outSize).divide(two, PRECISION, RoundingMode.CEILING)
				.toBigInteger();
		BigInteger mid = outEdge.add(m);

		Coins coins = new Coins(this.key, mid);
		BigInteger x = sampleHGD(inRange, outRange, mid, coins);

		if (ctxt.compareTo(mid) <= 0) {
			inRange = new ValueRange(inEdge.add(BigInteger.ONE), x);
			outRange = new ValueRange(outEdge.add(BigInteger.ONE), mid);
		} else {
			inRange = new ValueRange(x.add(BigInteger.ONE), inEdge.add(inSize));
			outRange = new ValueRange(mid.add(BigInteger.ONE), outEdge.add(outSize));
		}

		return this.decryptRecursive(ctxt, inRange, outRange);
	}

	/**
	 * Uniformly select a number from the range using the bit list as a source of randomness
	 *
	 * @param outRange
	 * @param coins
	 * @return
	 */
	private static BigInteger sampleUniform(ValueRange inRange, Coins coins) {

		ValueRange curRange = new ValueRange(inRange);

		while (curRange.size().compareTo(BigInteger.ONE) > 0) {

			// System.out.println(curRange.start + " " + curRange.end);

			BigInteger mid = curRange.start.add(curRange.end).divide(new BigInteger("2"));

			boolean bit = coins.next();
			if (bit == false)
				curRange.end = mid;
			else if (bit == true)
				curRange.start = mid.add(BigInteger.ONE);
			else
				throw new RuntimeException("Unexpected bit value");
		}

		return curRange.start;
	}

	private BigInteger sampleHGD(ValueRange inRange, ValueRange outRange,
			BigInteger nSample, Coins coins) {

		BigInteger inSize = inRange.size();
		BigInteger outSize = outRange.size();

		BigInteger nSampleIndex = nSample.subtract(outRange.start).add(BigInteger.ONE);

		if (inSize.compareTo(outSize) == 0)
			return inRange.start.add(nSampleIndex).subtract(BigInteger.ONE);

		BigInteger inSampleNum = hgd.rhyper(nSampleIndex, inSize, outSize, coins);

		if (inSampleNum.compareTo(BigInteger.ZERO) == 0)
			return inRange.start;
		else if (inSampleNum.compareTo(inSize) == 0)
			return inRange.end;
		else {
			return inRange.start.add(inSampleNum);
		}
	}

	public static void main(String[] args) {
		OPE o = new OPE("key");

		long start = System.currentTimeMillis();
		for (int i = 0; i < 1000; i++) {

			BigInteger p = new BigInteger("" + i);

			BigInteger e = o.encrypt(p);
			BigInteger d = o.decrypt(e);

			if (d.compareTo(p) != 0)
				throw new RuntimeException("failed: " + p + " " + d);

			if (i % 1000 == 0)
				System.out.println(e + " " + d);
		}
		
		long end = System.currentTimeMillis();
		System.out.println("Done in " + (end - start) + " ms");
	}
}
