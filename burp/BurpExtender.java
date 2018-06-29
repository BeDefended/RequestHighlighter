/**
 * Created by BeDefended on 26/05/2018.
 * Copyright (c) 2018 BeDefended. All rights reserved.
 * MIT Licensed
 */

package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IProxyListener, IContextMenuFactory, ActionListener
{

	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	
	private static final String PLUGIN_NAME = "Request Highlighter";
	private static final int CHARS_NUMBER = 10;
	private static final int MIN_LEN = 3;
	
	private HashSet<String> colors;	
	
	private Map<String, String> tags;
	
	private JMenu submenu;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName(PLUGIN_NAME);
        
        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
                
        tags = new HashMap<String, String>();
        
        //defining colors for highlight
        colors = new HashSet<String>();
        colors.add("red");
        colors.add("blue");
        colors.add("pink");
        colors.add("green");
        colors.add("magenta");
        colors.add("cyan");
        colors.add("gray");
        colors.add("yellow");
        
                
        // register as a Proxy listener
        callbacks.registerProxyListener(this);
        
        callbacks.registerContextMenuFactory(this);
        
		
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		
		if(!messageIsRequest)
			return;
		
		IRequestInfo request = helpers.analyzeRequest(message.getMessageInfo().getRequest());
				
		String headers = request.getHeaders().toString();
		
		for (Map.Entry<String, String> entry : tags.entrySet())
		{
			if(headers.contains(entry.getKey()))
			{
				message.getMessageInfo().setHighlight(tags.get(entry.getKey()));
				
				break;
			}
		}
		
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		
		if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
		{			
			int[] offsets = invocation.getSelectionBounds();

			IHttpRequestResponse req = invocation.getSelectedMessages()[0];
			
			String selectedText = getSelection(req.getRequest(), offsets);
						
			List<JMenuItem> menu = new ArrayList<JMenuItem>();
			
			String color = tags.get(selectedText);
			
			if(color != null)
			{
				//Is present			
				JMenuItem main = new JMenuItem(PLUGIN_NAME + " - disable "+color+" highlight");
				main.setActionCommand(selectedText);
				main.addActionListener(this);
				menu.add(main);
				
			}
			else
			{
				if(selectedText.length() >= MIN_LEN)
				{
				
					Iterator<String> it = colors.iterator();
					
					if(it.hasNext())
					{
						JMenuItem main = new JMenuItem(PLUGIN_NAME + " - add highlight");
						main.setActionCommand(selectedText);
						main.addActionListener(this);
						menu.add(main);
					}
					else
					{
						JMenuItem main = new JMenuItem(PLUGIN_NAME + " - max num (8) reached");
						menu.add(main);
						main.setEnabled(false);
					}
					
				}
												
			}
				
			
			
			if(tags.size() > 0)
			{
				
				menu.add(submenu);
			}
			
			return menu;
			
			
		}
				
		
		return null;
	}
	

    private String getSelection(byte[] message, int[] offsets) {
        if (offsets == null || message == null) return "";
        
        if (offsets.length < 2 || offsets[0] == offsets[1]) return "";
        
        byte[] selection = Arrays.copyOfRange(message, offsets[0], offsets[1]);
        
        return new String(selection);
    }
    

    private JMenu generateSubmenu()
    {
    	JMenu main = new JMenu("Disable "+PLUGIN_NAME);
				
		for (Map.Entry<String, String> entry : tags.entrySet())
		{
			String text;
			
			if(entry.getKey().length() > (CHARS_NUMBER*2)+5)
			{
				//The selected string is too long to be displayed
				text = entry.getKey().substring(0, CHARS_NUMBER)+" ... "+entry.getKey().substring(entry.getKey().length() - CHARS_NUMBER);
			}
			else
			{
				text = entry.getKey();
			}
			
			main.add(CreateMenuItem(entry.getValue()+" - "+text, entry.getKey(), this));
		}
		
		return main;
    }
    

	public static JMenuItem CreateMenuItem(String name, String command, ActionListener listener){
    	JMenuItem newItem = new JMenuItem(name);
		newItem.setActionCommand(command);
		newItem.addActionListener(listener);
		
		return newItem;
	}


	@Override
	public void actionPerformed(ActionEvent e) {
		
		String selectedText = e.getActionCommand();
		
		String color = tags.get(selectedText);
		
		if(color != null)
		{
			//Already highlighted --> remove
			
			tags.remove(selectedText);
			
			colors.add(color);
			
			stdout.println("Remove TAG color: "+color);
		}
		else
		{
			//Not present --> add
			
			Iterator<String> it = colors.iterator();
			
			if(it.hasNext())
			{
				color = it.next();
				
				tags.put(selectedText, color);
				
				colors.remove(color);
				
				stdout.println("Add TAG color: "+color);
			}
			else
			{
				stdout.println("Error - no color available, remove one and retry.");
			}
			
		}
		
		this.submenu = this.generateSubmenu();
				
	}

	
}
