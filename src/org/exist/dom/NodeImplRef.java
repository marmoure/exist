package org.exist.dom;

/**
 * Holds a mutable reference to a NodeImpl, used to pass a node by reference.
 *
 * @author <a href="mailto:piotr@ideanest.com">Piotr Kaminski</a>
 */
public class NodeImplRef {
	
	public NodeImplRef() {}
	public NodeImplRef(NodeImpl node) {this.node = node;}
	
	public NodeImpl node;

}
