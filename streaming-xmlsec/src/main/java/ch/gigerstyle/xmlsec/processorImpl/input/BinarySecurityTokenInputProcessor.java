package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.crypto.Crypto;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 5:55:30 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class BinarySecurityTokenInputProcessor extends AbstractInputProcessor implements SecurityTokenProvider {

    //todo this processor is not usable multiple times! Enforce one time usage! Other processors have the same "problem"
    private BinarySecurityTokenType currentBinarySecurityTokenType;
    private boolean isFinishedcurrentBinarySecurityToken = false;

    private SecurityToken securityToken;

    public BinarySecurityTokenInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (currentBinarySecurityTokenType != null) {
            try {
                isFinishedcurrentBinarySecurityToken = currentBinarySecurityTokenType.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentBinarySecurityToken) {
                    currentBinarySecurityTokenType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        }
        else if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
                currentBinarySecurityTokenType = new BinarySecurityTokenType(startElement);
            }
        }

        if (currentBinarySecurityTokenType != null && isFinishedcurrentBinarySecurityToken) {
            try {
                if (currentBinarySecurityTokenType.getId() != null) {
                    securityContext.registerSecurityTokenProvider(currentBinarySecurityTokenType.getId(), this);
                }
            } finally {
                inputProcessorChain.removeProcessor(this);
                isFinishedcurrentBinarySecurityToken = false;
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }

    public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {
        return SecurityTokenFactory.newInstance().getSecurityToken(currentBinarySecurityTokenType, crypto, getSecurityProperties().getCallbackHandler());
    }
}
