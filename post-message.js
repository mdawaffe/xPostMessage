/*

LICENSE: GPL2+

targetFrameChannel = new xPostMessage( targetFrame, targetFrameName, targetProxyURL, sourceProxyURL );

targetFrameChannel.postMessage( message );

xPostMessage.subscribe( callback, sourceOrigin );

@todo! postMessage channel accepts objects, returns JSON strings.  hash channel accepts objects, returns objects.
@todo? otherFrame.subscribe( callback ); // match sourceOrigin AND sourceFrame
@todo? NSL secures a two-way communication channel, but xPostMessage creates a new channel for each direction.
      In theory, we could re-use the secrets if the TARGET wants to send a message to the SOURCE.
@todo? talk to non-frame windows (window.open)

Goals:
Secure (confidential and authenticated) in all supported browsers
No cookies
No flash/plugins
No polling

References:
Resize event eliminates hash polling: http://shouldersofgiants.co.uk/Blog/post/2009/08/17/Another-Cross-Domain-iFrame-Communication-Technique.aspx
Needham-Schroeder-Lowe secures communication over hash channel: http://seclab.stanford.edu/websec/frames/post-message.pdf

Other APIs:
Porthole - https://github.com/ternarylabs/porthole/ (hash channel insecure)
xssinterface - http://code.google.com/p/xssinterface/ (hash channel insecure)
easyXDM - http://easyxdm.net/wp/ (flash, hash channel insecure)
jQuery postMessage - http://benalman.com/projects/jquery-postmessage-plugin/ (polling, hash channel insecure and does not use proxies so is faster but pollutes window.location)
*/

(function( window, undefined ) {
/**
 * Set up the xPostMessage object.
 * <code>
 * someFrameChannel = new xPostMessage( someFrame, 'some-frame', 'http://someframe.example.com/proxy.html', 'http://example.com/proxy.html' );
 * someFrameChannel.postMessage( 'some message' );
 *
 * @todo Allow xPostMessage( iframeElement, targetProxyURL, sourceProxyURL ) in addition?
 *
 * @param Window object targeFrame
 * @param string targetFrameName iframe's name, or 'parent' for the currenty window's parent, or 'top' for the top window.
 * @param string targetProxyURL
 * @param string sourceProxyURL
 */
var xPostMessage = function( targetFrame, targetFrameName, targetProxyURL, sourceProxyURL ) {
	var i, that = this;

	if ( !targetFrame || !targetFrameName || !targetProxyURL || !sourceProxyURL ) {
		return false;
	}

	// @todo return already created objects?

	this.id = UUID.generate();
	xPostMessage.objects[this.id] = this;

	this.targetFrame = targetFrame;
	this.targetFrameName = targetFrameName;
	this.targetProxyURL = targetProxyURL;
	this.sourceProxyURL = sourceProxyURL;

	this.sourceOrigin = xPostMessage.originFromURL();
	this.targetOrigin = xPostMessage.originFromURL( this.targetProxyURL );

	this.proxy = false;

	this.ready = false;

	this.init();
};

/**
 * Stores all previously created xPostMessage objects by ID
 */
xPostMessage.objects = {};

/**
 * Debug
 */
if ( console.log.apply ) {
	xPostMessage.log = function() {
		var args = [ window.location.toString() ], i;
		for ( i = 0; i < arguments.length; i++ ) {
			args[args.length] = arguments[i];
		}

		console.log.apply( console, args );
	};
} else {
	xPostMessage.logI = 0;
	xPostMessage.log = function() {
		console.log( xPostMessage.logI, window.location.toString() );
		for ( i = 0; i < arguments.length; i++ ) {
			console.log( xPostMessage.logI, arguments[i] )
		}
		xPostMessage.logI = xPostMessage.logI + 1;
	};
}

/**
 * Extracts scheme + domain + port.
 *
 * @param string URL
 * @return string origin
 */
xPostMessage.originFromURL = function( url ) {
	if ( undefined === url ) {
		url = window.location.toString();
	}

	try {
		return url.match( /^\w+:\/\/[^\/]+/ )[0];
	} catch ( e ) {
		return false;
	}
};

/**
 * Event binder
 */
if ( window.addEventListener ) {
	xPostMessage.binder = function( element, type, callback ) {
		element.addEventListener( type, callback, false );
	};
} else {
	xPostMessage.binder = function( element, type, callback ) {
		element.attachEvent( 'on' + type, function( event ) { callback.call( element, event ); }, false );
	};
}

/**
 * Stores PubSub callbacks.
 */
xPostMessage.dispatchees = {};

/**
 * Pub
 */
xPostMessage.dispatchMessageEvents = function( event ) {
	var i, dispatchees;

	if ( undefined === xPostMessage.dispatchees[event.origin] ) {
		return;
	}

	dispatchees = xPostMessage.dispatchees[event.origin].slice(0);
	for ( i = 0; i < dispatchees.length; i++ ) {
		dispatchees[i]( event );
	}
};

/**
 * Sub
 */
xPostMessage.subscribe = function( callback, sourceOrigin ) {
	sourceOrigin = sourceOrigin || xPostMessage.originFromURL( window.location.toString() );

	if ( undefined === xPostMessage.dispatchees[sourceOrigin] ) {
		xPostMessage.dispatchees[sourceOrigin] = [];
	}

	xPostMessage.dispatchees[sourceOrigin][xPostMessage.dispatchees[sourceOrigin].length] = callback;
};

/**
 * Send a message to the target frame.
 *
 * @param string message
 * @return bool
 */
xPostMessage.prototype.postMessage = function( message ) {
	if ( this.ready ) {
		return this._postMessage( message );
	}

	return false;
};

if ( false && undefined !== window.postMessage ) {
	// HTML5 window.postMessage channel

	// Tell Pub to listen to message events
	xPostMessage.binder( window, 'message', xPostMessage.dispatchMessageEvents );

	// Stub
	xPostMessage.initProxy = function() {};

	// Stub
	xPostMessage.prototype.init = function() {
		this.ready = true;
	};

	/**
	 * Wrapper for window.postMessage.  Handles targeOrigin.
	 *
	 * @param string message The message to send to the other frame.
	 */
	xPostMessage.prototype._postMessage = function( message ) {
		try {
			message = JSON.stringify( message );
		} catch ( e ) {
			return false;
		}

		return this.targetFrame.postMessage( message, this.targetOrigin );
	};
} else {
	// Legacy #fragment channel

	// @todo - direct access for same origin

	/**
	 * Stores the single proxy details for this window.  Only used by proxy windows.
	 */
	xPostMessage.proxy = {};

	/**
	 * Stores the proxies used to send messages to this window.  Only used by TARGET windows.
	 */
	xPostMessage.proxyOrigins = {};

	/**
	 * Setus up the proxied connection using Needham-Schroeder-Lowe handshake.
	 * (The SOURCE is Alice.  The TARGET is Bob.)
	 */
	xPostMessage.prototype.init = function() {
		var that = this, i, data;

		// Nonces a.k.a. Needham-Schroeder-Lowe secrets
		this.NA = UUID.generate();
		this.NB = undefined;

		// SOURCE should SEND: NA,URIA

		// Create the iframe proxy
		this.proxy = window.document.createElement( 'iframe' );

		data = JSON.stringify( {
			stage      : 1,
			NA         : this.NA,
			URIA       : this.sourceProxyURL,
			originID   : this.id, // So that TARGET can identify which source is talking to it
			targetName : this.targetFrameName // So that the proxy can identify which TARGET to forward to
		} );

		this.proxy.src = this.targetProxyURL + '#' + data;
		this.proxy.frameBorder = 1;
		this.proxy.width = 100;  // We'll change this to fire resize events.
		this.proxy.height = 100; // Constant.  IE7 doesn't notice height changes without more styling of the proxy HTML.

		window.document.body.appendChild( this.proxy );
	};

	/**
	 * onLoad/onResize handler for the proxy windows.
	 * Sets up the Needham-Schroeder-Lowe handshake.
	 * Passes messages to TARGET.
	 *
	 * @param Event event The onLoad/onResize event.
	 */
	xPostMessage.initProxy = function( event ) {
		var eventTarget = event.target || event.srcElement, // Normalize
		    // If possible, Use the event's window's location to (maybe?) help with edge cases.  Fallback to window's location.
		    eventHash = ( eventTarget && eventTarget.location.hash ) || window.location.hash,
		    data,
		    returnProxy, returnData, proxyOrigin,
		    xPostMessageObject, messageEvent;

		eventHash = eventHash.replace( /^#+/, '' );

		if ( 0 === eventHash.indexOf( '{%22' ) ) {
			// Safari encodes the hash, other browsers do not.  Normalize.
			eventHash = decodeURIComponent( eventHash );
		}

		try {
			data = JSON.parse( eventHash );

			if ( !data || !data.stage ) {
				return;
			}
		} catch ( e ) {
			return;
		}

		// Stages of the Needham-Schroeder-Lowe handshake
		switch ( data.stage ) {
		// Runs on load in the iframe proxy
		case 1 : // TARGET should RECV: NA,URIA and SEND: NA,NB,URIB
			if ( !data.NA || !data.URIA || !data.originID || !data.targetName ) {
				return;
			}

			// We've already done stage 1.  Bail.
			if ( xPostMessage.proxy.stage || xPostMessage.proxy.NA || xPostMessage.proxy.NB || xPostMessage.proxy.URIA || xPostMessage.proxy.URIB || xPostMessage.proxy.originID || xPostMessage.proxy.target ) {
				return;
			}

			// Store the Needham-Schroeder-Lowe secrets in the proxy.
			xPostMessage.proxy.stage    = 1;
			xPostMessage.proxy.NA       = data.NA;
			xPostMessage.proxy.URIA     = data.URIA;
			xPostMessage.proxy.originID = data.originID;
			xPostMessage.proxy.target   = xPostMessage.getFrame( data.targetName );

			// We can't find the TARGET.  Bail.
			if ( !xPostMessage.proxy.target ) {
				return;
			}

			// The TARGET is already accepting messages from this xPostMessage object of this SOURCE.  Bail.
			if ( xPostMessage.proxy.target.xPostMessage.proxyOrigins[xPostMessage.proxy.originID] ) {
				return;
			}

			// Store the Needham-Schroeder-Lowe secrets in the TARGET.
			proxyOrigin = {
				NA       : xPostMessage.proxy.NA,
				URIA     : xPostMessage.proxy.URIA,
				NB       : xPostMessage.proxy.target.UUID.generate(),
				URIB     : xPostMessage.proxy.target.location.toString().replace( /#.*$/, '' )
			};

			xPostMessage.proxy.target.xPostMessage.proxyOrigins[xPostMessage.proxy.originID] = proxyOrigin;

			// Create disposable iframe proxy for Needham-Schroeder-Lowe response.
			returnProxy = xPostMessage.proxy.target.document.createElement( 'iframe' );
			returnData  = JSON.stringify( {
				stage      : 2,
				NA         : proxyOrigin.NA,
				NB         : proxyOrigin.NB,
				URIB       : proxyOrigin.URIB,
				originID   : xPostMessage.proxy.originID
			} );

			returnProxy.src = proxyOrigin.URIA + '#' + returnData;
			returnProxy.frameBorder = 1;
			returnProxy.width = 100;
			returnProxy.height = 100;

			xPostMessage.binder( returnProxy, 'load', function() {
				// Needham-Schroeder-Lowe response sent.  iFrame no longer needed.
				setTimeout( function() { returnProxy.parentNode.removeChild( returnProxy ); }, 1000 );
			} );

			xPostMessage.proxy.target.document.body.appendChild( returnProxy );
			break;
		// Runs on load in the disposable iframe proxy
		case 2 : // SOURCE should RECV: NA,NB,URIB and SEND: NB
			if ( !data.NA || !data.NB || !data.URIB || !data.originID ) {
				return;
			}

			// This disposable iframe has already been used.  Should never happen.  Bail.
			if ( xPostMessage.proxy.stage || xPostMessage.proxy.NA || xPostMessage.proxy.NB || xPostMessage.proxy.URIA || xPostMessage.proxy.URIB || xPostMessage.proxy.originID || xPostMessage.proxy.target ) {
				return;
			}

			// Store the Needham-Schroeder-Lowe secrets in the disposable iframe proxy.
			xPostMessage.proxy.stage    = 2;
			xPostMessage.proxy.NA       = data.NA;
			xPostMessage.proxy.NB       = data.NB;
			xPostMessage.proxy.URIB     = data.URIB;
			xPostMessage.proxy.originID = data.originID;
			xPostMessage.proxy.target   = xPostMessage.getFrameByXID( xPostMessage.proxy.originID );

			// We can't find the disposable iframe's target (which is the channel's SOURCE).  Bail.
			if ( !xPostMessage.proxy.target ) {
				return;
			}

			// The SOURCE's xPostMessage object
			xPostMessageObject = xPostMessage.proxy.target.xPostMessage.objects[xPostMessage.proxy.originID];

			// @todo - better check than origin?
			if ( xPostMessageObject.NB || xPostMessage.originFromURL( xPostMessage.proxy.URIB ) !== xPostMessageObject.targetOrigin ) {
				return;
			}

			// Store the Needham-Schroeder-Lowe secrets in the SOURCE.
			xPostMessageObject.NB = xPostMessage.proxy.NB;

			returnData = JSON.stringify( {
				stage : 3,
				NB    : xPostMessageObject.NB
			} );

			// Use the original (used previously in stage 1) iframe proxy to send last Needham-Schroeder-Lowe handshake stage
			xPostMessageObject.proxy.src = xPostMessageObject.targetProxyURL + '#' + returnData;
			xPostMessageObject.proxy.width = xPostMessageObject.proxy.width < 200 ? 300 : 100;
			xPostMessageObject.ready = true;
			break;
		// Runs on resize in the iframe proxy
		case 3 : // TARGET should RECV: NB and become ready.
			if ( !data.NB ) {
				return;
			}

			// We haven't done stage 1 yet, or we've already done stage 3.  Bail.
			if ( 1 !== xPostMessage.proxy.stage || !xPostMessage.proxy.NA || !xPostMessage.proxy.URIA || !xPostMessage.proxy.originID || !xPostMessage.proxy.target ) {
				return;
			}

			// No TARGET or Needham-Schroeder-Lowe secrets don't match.  Bail.
			if ( !xPostMessage.proxy.target || !xPostMessage.proxy.target.xPostMessage.proxyOrigins[xPostMessage.proxy.originID] || data.NB !== xPostMessage.proxy.target.xPostMessage.proxyOrigins[xPostMessage.proxy.originID].NB ) {
				return;
			}

			// Store Needham-Schroeder-Lowe secrets in iframe proxy
			xPostMessage.proxy.stage = 3;
			xPostMessage.proxy.NB    = data.NB;
			break;
		// Runs on resize
		case 4 : // TARGET should RECV: A real message
			if ( !data.NA || !data.NB ) {
				return;
			}

			// Needham-Schroeder-Lowe secrets don't match.  Bail.
			if ( data.NA !== xPostMessage.proxy.NA || data.NB !== xPostMessage.proxy.NB ) {
				return;
			}

			// The handshake has not completed.  Bail.
			if ( 3 !== xPostMessage.proxy.stage ) {
				return;
			}

			// Spoof a message event.
			// @todo, can we fire a real browser event cross-browser?  That way we could stick to using event listeners for pubsub.
			messageEvent = {
				data   : data.message,
				source : window.parent, // The proxy is always a child of the source
				origin : xPostMessage.originFromURL( xPostMessage.proxy.target.xPostMessage.proxyOrigins[xPostMessage.proxy.originID].URIA )
			};

			// Pub
			xPostMessage.proxy.target.xPostMessage.dispatchMessageEvents( messageEvent );
			break;
		}
	};

	/**
	 * Recursive frame lookup by frame name starting at the given window in the frame hierarchy.
	 *
	 * @param string name
	 * @param Window object start
	 * @return bool|Window object of the frame
	 */
	xPostMessage.getFrame = function( name, start ) {
		var i, frame;

		if ( 'parent' === name ) {
			// xPostMessage.getFrame() is always called in the proxy, which is the child of the source.  So the source's parent is the proxy's grandparent.
			return window.parent.parent;
		} else if ( 'top' === name ) {
			return window.top;
		}

		start = start || window.top;

		if ( start.frames[name] ) {
			return start.frames[name];
		}

		for ( i = 0; i < start.frames.length; i++ ) {
			frame = xPostMessage.getFrame( name, start.frames[i] );
			if ( frame ) {
				return frame;
			}
		}

		return false;
	};

	/**
	 * Recursive frame lookup by xPostMessage ID starting at the givin window in the frame hierarchy.
	 *
	 * @param xID
	 * @param Window object start
	 * @return bool|Window object of the frame
	 */
	xPostMessage.getFrameByXID = function( xID, start ) {
		var i, frame;

		start = start || window.top;

		try {
			if ( start.xPostMessage && start.xPostMessage.objects[xID] ) {
				return start;
			}
		} catch( e ) {}

		for ( i = 0; i < start.frames.length; i++ ) {
			frame = xPostMessage.getFrameByXID( xID, start.frames[i] );
			if ( frame ) {
				return frame;
			}
		}

		return false;
	};

	/**
	 * Wrapper for communication via Needham-Schroeder-Lowe pre-secured iframe proxies.  Handles targeOrigin.
	 *
	 * @param string message The message to send to the other frame.
	 */
	xPostMessage.prototype._postMessage = function( data ) {
		var envelope = {
			stage   : 4,
			NA      : this.NA,
			NB      : this.NB,
			message : data
		};

		try {
			envelope = JSON.stringify( envelope );
		} catch ( e ) {
			return false;
		}

		this.proxy.src = this.targetProxyURL + '#' + envelope;
		this.proxy.width = this.proxy.width < 200 ? 300 : 100;
		return true;
	};
}

window.xPostMessage  = xPostMessage;
})( window );
