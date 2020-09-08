package user11681.shortcode;

@FunctionalInterface
public interface ThrowingIntConsumer {
    void accept(int i) throws Throwable;
}
