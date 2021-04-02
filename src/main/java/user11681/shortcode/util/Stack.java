package user11681.shortcode.util;

import java.util.ArrayList;

public class Stack<E> extends ArrayList<E> {
    public E peek() {
        return this.get(this.size() - 1);
    }

    public E pop() {
        return this.remove(this.size() - 1);
    }
}
