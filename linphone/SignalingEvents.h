#ifndef __SIGNALING_EVENTS_H__
#define __SIGNALING_EVENTS_H__

#include <string>
namespace mrtc {
enum RegisterReason
{
	RegisterReasonNone,
	RegisterReasonNoResponse,
	RegisterReasonBadCredentials,
	RegisterReasonUnknown
};

enum CallReason
{
	CallReasonNone,
	CallReasonNoResponse,
	CallReasonBadCredentials,
	CallReasonDeclined,
	CallReasonNotFound,
	CallReasonNotAnswer,
	CallReasonBusy,
	CallReasonUnknown
};

typedef struct SignalingParameters
{
	std::string from;
	std::string to;
	std::string callId;
	std::string lsdp;
	std::string rsdp;
	std::string candiate;
} SignalingParameters;

/**
	* Callback interface for messages delivered on signaling channel.
	*/
class SignalingEvents
{
public:
	/**
		* Callback fired once register/unregister successful
		* @param registered true for register successful, false for unregister successful
		*/
	virtual void onRegistered(bool registered) = 0;

	/**
		* Callback fired once register/unregister failure
		* @param reason register/unregister failure reason
		*/
	virtual void onRegisterFailure(RegisterReason reason) = 0;

	/**
		* Callback fired once new incoming call received
		* @param SignalingParameters are extracted.
		*/
	virtual void onCallIncoming(const SignalingParameters &params) = 0;

	/**
		* Callback fired once outgoing call received ring back message
		*/
	virtual void onCallRingback() = 0;

	/**
		* Callback fired once incoming call send ringing message
		*/
	virtual void onCallRinging() = 0;

	/**
		* Callback fired once call connected
		*/
	virtual void onCallConnected() = 0;

	/**
		* Callback fired once call terminated
		*/
	virtual void onCallEnded() = 0;

	/**
		* Callback fired once call failure
		* @param reason call failure reason
		*/
	virtual void onCallFailure(CallReason reason) = 0;

	/**
		* Callback fired once remote SDP is received
		*/
	virtual void onRemoteDescription(const std::string &sdp) = 0;

	/**
		* Callback fired once remote Ice candiate is received
		*/
	virtual void onRemoteIceCandidate(const std::string &candiate) = 0;

	/**
		* Callback fired once remote Ice candiate removals is received
		*/
	virtual void onRemoteIceCandidatesRemoved(const std::string &candiate) = 0;
};
} // namespace mrtc
#endif
