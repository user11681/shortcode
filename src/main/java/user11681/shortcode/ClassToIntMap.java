package user11681.shortcode;

import it.unimi.dsi.fastutil.objects.Reference2IntOpenHashMap;

public class ClassToIntMap extends Reference2IntOpenHashMap<Class<?>> {
    protected static final int DEFAULT_VALUE = -1;

    public ClassToIntMap(Class<?>[] k, int[] v) {
        super(k, v, DEFAULT_LOAD_FACTOR);

        this.defRetValue = DEFAULT_VALUE;
    }
}
