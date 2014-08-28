package org.elasticsearch.plugins.security.filter;

import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import junit.framework.Assert;

import org.elasticsearch.plugins.security.filter.AbstractPermTests.TestCallback;
import org.elasticsearch.plugins.security.service.permission.PermEvaluator;
import org.junit.Test;

public class DlsTests extends AbstractPermTests {
    
    @Test
    public void testNormal1() throws Exception {

        final List<String> tokens = new ArrayList<String>();
        tokens.add("default");
        tokens.add("everyone");
        final PermEvaluator<List<String>> evaluator = new PermDlsEvaluator(
                loadFile("dls_test_normal.json"));
        assertTrue(evaluator.evaluatePerm(null, null,
                InetAddress.getByName("8.8.8.8"), null).equals(tokens));
         
    }
    
    @Test
    public void testNormal2() throws Exception {

        final List<String> tokens = new ArrayList<String>();
        tokens.add("guesttoken");
        final PermEvaluator<List<String>> evaluator = new PermDlsEvaluator(
                loadFile("dls_test_normal.json"));
        assertTrue(evaluator.evaluatePerm(null, null,
                InetAddress.getByName("8.8.8.8"), new TestCallback("Guest", "guest")).equals(tokens));
         
    }
    
    @Test
    public void testEmptyArraysAllow() throws Exception {

        final List<String> tokens = new ArrayList<String>();
        tokens.add("guesttoken");
        
        final PermEvaluator<List<String>> evaluator = new PermDlsEvaluator(
                loadFile("dls_allow_emptyarray.json"));
       
        org.junit.Assert.assertEquals(tokens, evaluator.evaluatePerm(null, null,
                InetAddress.getByName("8.8.8.8"), null));
            

    }
    
    @Test
    public void testEmptyArrays() throws Exception {

        final List<String> tokens = new ArrayList<String>();
        
        final PermEvaluator<List<String>> evaluator = new PermDlsEvaluator(
                loadFile("dls_denyall_emptyarray.json"));
       
        org.junit.Assert.assertEquals(tokens, evaluator.evaluatePerm(null, null,
                InetAddress.getByName("8.8.8.8"), null));
            

    }

    
    @Test
    public void issueDls1() throws Exception {

        final List<String> tokens = new ArrayList<String>();
        final PermEvaluator<List<String>> evaluator = new PermDlsEvaluator(
                loadFile("issues/dls1/rules.json"));
        assertTrue(evaluator.evaluatePerm(null, null,
                InetAddress.getByName("8.8.8.8"), null).equals(tokens));
         
    }
    
    @Test
    public void issueDls2() throws Exception {

        List<String> tokens = new ArrayList<String>();
        tokens.add("t_everyone");
        
        final List<String> indices = new ArrayList<String>();
		indices.add("testindex1");
	
        
        final PermEvaluator<List<String>> evaluator = new PermDlsEvaluator(
                loadFile("issues/dls2/rules.json"));
        assertTrue(evaluator.evaluatePerm(indices, null,
                InetAddress.getByName("8.8.8.8"), null).equals(tokens));
         
    }
    

}
