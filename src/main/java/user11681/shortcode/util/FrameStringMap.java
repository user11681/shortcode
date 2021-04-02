package user11681.shortcode.util;

public class FrameStringMap {
    private final String[] values = {"new", "full", "append", "chop", "same", "same1"};

    public String get(int type) {
        return this.values[type + 1];
    }
}
