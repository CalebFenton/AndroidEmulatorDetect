package org.cf.emulatordetect;

import android.content.Context;
import android.os.Build;
import android.os.Debug;
import android.telephony.TelephonyManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * References:
 * https://users.ece.cmu.edu/~tvidas/papers/ASIACCS14.pdf
 * http://stackoverflow.com/questions/2799097/how-can-i-detect-when-an-android-application-is-running-in-the-emulator
 * http://webcache.googleusercontent.com/search?q=cache:7NRl_DBrk2AJ:www.oguzhantopgul.com/2014/12/android-malware-evasion-techniques.html+&cd=6&hl=en&ct=clnk&gl=us
 * https://github.com/Fuzion24/AndroidHostileEnvironmentDetection
 */
public class Detector {
    private final Context context;

    Detector(Context context) {
        this.context = context;
    }

    private static boolean hasEth0Interface() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.getName().equals("eth0"))
                    return true;
            }
        } catch (SocketException ex) {
        }
        return false;
    }

    private static boolean hasQemuCpuInfo() {
        try {
            BufferedReader cpuInfoReader = new BufferedReader(new FileReader("/proc/cpuinfo"));
            String line;
            while ((line = cpuInfoReader.readLine()) != null) {
                if (line.contains("Goldfish"))
                    return true;
            }
        } catch (Exception e) {
        }
        return false;
    }

    private static boolean hasQemuFile() {
        return new File("/init.goldfish.rc").exists()
                || new File("/sys/qemu_trace").exists()
                || new File("/system/bin/qemud").exists();

    }

    private static String getProp(Context ctx, String propName) {
        try {
            ClassLoader cl = ctx.getClassLoader();
            Class<?> klazz = cl.loadClass("android.os.properties");
            Method getProp = klazz.getMethod("get", String.class);
            Object[] params = {propName};
            return (String) getProp.invoke(klazz, params);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private boolean hasQemuBuildProps() {
        return "goldfish".equals(getProp(context, "ro.hardware"))
                || "ranchu".equals(getProp(context, "ro.hardware"))
                || "generic".equals(getProp(context, "ro.product.device"))
                || "1".equals(getProp(context, "ro.kernel.qemu"))
                || "0".equals(getProp(context, "ro.secure"));
    }

    private boolean isNotUserBuild() {
        //Other builds of android that are not production usually have build types of "eng", "debug", etc...
        //Although this doesn't denote having an emulator, there is a possibility that the user is more intelligent
        //than a normal Android user and thus increases the risk of getting caught .. avoid that situation

        return !"user".equals(getProp(context, "ro.build.type"));
    }

    private boolean isDebuggerConnected() {
        return Debug.isDebuggerConnected();
    }

    private boolean hasEmulatorBuildProp() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk") || Build.MODEL.contains("sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || Build.PRODUCT.contains("google_sdk") || Build.PRODUCT.contains("sdk")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.BOARD.contains("unknown")
                || Build.ID.contains("FRF91")
                || Build.MANUFACTURER.contains("unknown")
                || Build.SERIAL == null
                || Build.TAGS.contains("test-keys")
                || Build.USER.contains("android-build")
                ;
    }

    private boolean hasEmulatorTelephonyProperty() {
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        return "Android".equals(tm.getNetworkOperatorName())
                || "Android".equals(tm.getSimOperator())
                || "000000000000000".equals(tm.getDeviceId()) || tm.getDeviceId().matches("^0+$")
                || tm.getLine1Number().startsWith("155552155")
                || tm.getSubscriberId().endsWith("0000000000")
                || "15552175049".equals(tm.getVoiceMailNumber())
                ;
    }

    boolean isEmulator() {
        return hasEmulatorTelephonyProperty()
                || hasEmulatorBuildProp()
                || hasQemuBuildProps()
                || hasQemuCpuInfo()
                || hasQemuFile()
                || hasEth0Interface()
                || isNotUserBuild();
    }
}
