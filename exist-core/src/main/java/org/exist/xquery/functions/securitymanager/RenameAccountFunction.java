/*
 * eXist-db Open Source Native XML Database
 * Copyright (C) 2001 The eXist-db Authors
 *
 * info@exist-db.org
 * http://www.exist-db.org
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.exist.xquery.functions.securitymanager;

import org.exist.EXistException;
import org.exist.dom.QName;
import org.exist.security.*;
import org.exist.security.SecurityManager;
import org.exist.storage.DBBroker;
import org.exist.xquery.*;
import org.exist.xquery.value.*;

/**
 *
 * @author <a href="mailto:ccheraa@gmail.com">Adam RetterCharafeddine Cheraa</a>
 */
public class RenameAccountFunction extends BasicFunction {

    public final static QName qnRenameAccount = new QName("rename-account", SecurityManagerModule.NAMESPACE_URI, SecurityManagerModule.PREFIX);

    public final static FunctionSignature FNS_RENAME_ACCOUNT = new FunctionSignature(
            qnRenameAccount,
            "Renames a User Account.",
            new SequenceType[] {
                    new FunctionParameterSequenceType("username", Type.STRING, Cardinality.EXACTLY_ONE, "The User's username."),
                    new FunctionParameterSequenceType("new-username", Type.STRING, Cardinality.EXACTLY_ONE, "The User's new username.")
            },
            new SequenceType(Type.EMPTY, Cardinality.EMPTY_SEQUENCE)
    );

    public RenameAccountFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {

        final DBBroker broker = getContext().getBroker();
        final Subject currentUser = broker.getCurrentSubject();
        final SecurityManager securityManager = broker.getBrokerPool().getSecurityManager();

        final String username = args[0].getStringValue();

        try {
            if(isCalledAs(qnRenameAccount.getLocalPart())) {
                /* rename account */
                if (!currentUser.hasDbaRole() || currentUser.getName().equals(username)) {
                    throw new XPathException(this, "You can only change your account's username, or other accounts if you are a DBA.");
                }

                if (!securityManager.hasAccount(username)) {
                    throw new XPathException(this, "The user account with username " + username + " does not exist.");
                }

                Account account = securityManager.getAccount(username);
                final String newUsername = args[1].getStringValue();

                renameAccount(securityManager, account, newUsername);
            }
//        } catch(final PermissionDeniedException | EXistException pde) {
//            throw new XPathException(this, pde);
        } finally {}
        return Sequence.EMPTY_SEQUENCE;
    }

    private void renameAccount(SecurityManager securityManager, Account account, final String username) throws XPathException {
        account.setName(username);
        try {
            securityManager.updateAccount(account);
        } catch (PermissionDeniedException | EXistException e) {
            throw new XPathException(this, e);
        }
    }
}
