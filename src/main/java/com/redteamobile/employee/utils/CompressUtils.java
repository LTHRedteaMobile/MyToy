package com.redteamobile.employee.utils;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.util.ArrayList;
import java.util.List;

public class CompressUtils {
    public static void CompressWithPassword(String filePath, String destPath, String password) {
        try {
            ZipFile zipFile = new ZipFile(destPath);
            File file = new File(filePath);
            ZipParameters parameters = new ZipParameters();
            parameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE); // set compression method to store compression
            parameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_NORMAL); 
            parameters.setEncryptFiles(true);
            parameters.setEncryptionMethod(Zip4jConstants.ENC_METHOD_STANDARD);
            parameters.setPassword(password);
            zipFile.addFile(file, parameters);
        } catch (ZipException e) {
            e.printStackTrace();
        }
    }

    public static boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i=0; i<children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }
        return dir.delete();
    }

    public static void CompressWithoutFolder(String filePath, String destPath) throws Exception{
        try {
            File file2 = new File(destPath);
            if(file2.exists()){
                throw new FileAlreadyExistsException("文件已存在");
            }
            if(file2.getParentFile() != null){
                file2.getParentFile().mkdirs();
            }
            ZipFile zipFile = new ZipFile(destPath);
            File file = new File(filePath);
            ZipParameters parameters = new ZipParameters();
            parameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE); // set compression method to store compression
            parameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_NORMAL);
            loadFilename(zipFile,file,parameters);
        } catch (ZipException e) {
            e.printStackTrace();
        }
    }

    public static void Compress(String filePath, String destPath) throws Exception{
        try {
            File file2 = new File(destPath);
            if(file2.exists()){
                throw new FileAlreadyExistsException("文件已存在");
            }
            if(file2.getParentFile() != null){
                file2.getParentFile().mkdirs();
            }
            ZipFile zipFile = new ZipFile(destPath);
            File file = new File(filePath);
            ZipParameters parameters = new ZipParameters();
            parameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE); // set compression method to store compression
            parameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_NORMAL);
            addFie(zipFile,file,parameters);
        } catch (ZipException e) {
            e.printStackTrace();
        }
    }

    private static ZipFile addFie(ZipFile zipFile,File file,ZipParameters parameters) throws Exception{
        if(file.isFile()) {
            zipFile.addFile(file,parameters);
        }
        if(file.isDirectory()) {
            for(File f:file.listFiles()) {
                if(f.isDirectory()){
                    zipFile.addFolder(f,parameters);
                }else{
                    zipFile.addFile(f,parameters);
                }
            }
            zipFile.addFolder(file,parameters);
        }
        return zipFile;
    }

    private static ZipFile loadFilename(ZipFile zipFile,File file,ZipParameters parameters) throws Exception{
        List filenameList=new ArrayList();
        if(file.isFile()) {
            zipFile.addFile(file,parameters);
        }
        if(file.isDirectory()) {
            for(File f:file.listFiles()) {
                if(f.isDirectory()){
                    zipFile.addFolder(f,parameters);
                }else{
                    zipFile.addFile(f,parameters);
                }
            }
        }
        return zipFile;
    }

    public static void UncompressWithPassword(String zipFile, String destPath, String password) 
            throws ZipException, IOException {
        ZipFile zip = new ZipFile(zipFile);
        if (zip.isEncrypted()) {
            zip.setPassword(password);
        }
        System.out.println("compress" + destPath);
        zip.extractAll(destPath);
        //zip.extractAll(ConfigUtils.get("tmp.path"));
    }
    public static void Uncompress(String zipFile, String destPath) throws ZipException, IOException {
        ZipFile zip = new ZipFile(zipFile);
        System.out.println(destPath);
        zip.extractAll(destPath);
        //zip.extractAll(ConfigUtils.get("tmp.path"));
    }
}
