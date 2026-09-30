#ifndef WEB_SERVER_HANDLER_H
#define WEB_SERVER_HANDLER_H

#include <WebServer.h>
#include "GateController.h"
#include "GateMonitor.h"
#include "AuthConfig.h"
#include "AuthMiddleware.h"
#include "EmqxConfig.h"
#include "EmqxLogger.h"

class WebServerHandler {
public:
    WebServerHandler(GateController* gateController, GateMonitor* gateMonitor);
    ~WebServerHandler();
    void begin();
    void handleClient();

private:
    WebServer _server;
    GateController* _gateController;
    GateMonitor* _gateMonitor;
    AuthConfig* _authConfig;
    AuthMiddleware* _authMiddleware;
    EmqxConfig* _emqxConfig;
    EmqxLogger* _emqxLogger;
    
    // Route handlers
    void handleRoot();
    void handleHealth();
    void handleAuthInfo();
    void handleGateOpen();
    void handleGateClose();
    void handleGatePulse();
    void handleGateStatus();
    
    // Helper methods
    String buildStatusJson();
    void setupRoutes();
    
    // Authentication helpers
    bool requireAuthentication();
    void initializeAuth();
    
    // EMQX logging helpers
    void initializeEmqx();
    void logGateAction(const String& action, bool authorized);
};

#endif // WEB_SERVER_HANDLER_H
