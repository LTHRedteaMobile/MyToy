package com.redteamobile.employee.utils;


import com.google.common.hash.Hashing;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class FileHashUtils {
    private static final Logger LOG = LoggerFactory.getLogger(FileHashUtils.class);

    public static String getSHA256Checksum(String filename) throws Exception {
        File f = new File(filename);
        ByteArrayOutputStream bos = new ByteArrayOutputStream((int)f.length());
        BufferedInputStream in = null;
        byte[] file = null;
        try{
            in = new BufferedInputStream(new FileInputStream(f));
            int buf_size = 1024;
            byte[] buffer = new byte[buf_size];
            int len = 0;
            while(-1 != (len = in.read(buffer,0,buf_size))){
                bos.write(buffer,0,len);
            }
            file = bos.toByteArray();
        }catch (IOException e) {
            e.printStackTrace();
            throw e;
        }finally{
            try{
                in.close();
            }catch (IOException e) {
                e.printStackTrace();
            }
            bos.close();
        }
        return Hashing.sha256().hashBytes(file).toString();

    }

    public static String getFileHashValue(InputStream fis) {
        try {
            byte buffer[] = new byte[1024];
            MessageDigest md5 = MessageDigest.getInstance("SHA-256");
            for (int numRead = 0; (numRead = fis.read(buffer)) > 0; ) {
                md5.update(buffer, 0, numRead);
            }
            fis.close();

            return Hex.toHexString(md5.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
