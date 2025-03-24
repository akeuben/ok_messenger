package org.ok.app;

import org.ok.app.ui.Login;

import javax.swing.*;
import java.util.concurrent.atomic.AtomicReference;

public class WindowManager {
    private static JFrame currentWindow;

    public static JFrame get() {
        return currentWindow;
    }

    public static void set(JFrame window) {
        close();
        currentWindow = window;
    }

    public static void close() {
        if(currentWindow != null) currentWindow.dispose();
    }
}
