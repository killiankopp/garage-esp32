#include "WebServerHandler.h"
#include "Config.h"

WebServerHandler::WebServerHandler(GateController* gateController, GateMonitor* gateMonitor) 
    : _server(SERVER_PORT), _gateController(gateController), _gateMonitor(gateMonitor),
      _authConfig(nullptr), _authMiddleware(nullptr), _emqxConfig(nullptr), _emqxLogger(nullptr) {
}

WebServerHandler::~WebServerHandler() {
    delete _authMiddleware;
    delete _emqxLogger;
    delete _emqxConfig;
}

void WebServerHandler::begin() {
    initializeAuth();
    initializeEmqx();
    setupRoutes();
    _server.begin();
    Serial.println("HTTP server started");
}

void WebServerHandler::handleClient() {
    _server.handleClient();
    
    // Maintain EMQX connection
    if (_emqxLogger) {
        _emqxLogger->loop();
    }
}

void WebServerHandler::setupRoutes() {
    // Bind methods to this instance
    _server.on("/", [this]() { handleRoot(); });
    _server.on("/health", [this]() { handleHealth(); });
    _server.on("/auth/info", [this]() { handleAuthInfo(); });
    _server.on("/gate/open", [this]() { handleGateOpen(); });
    _server.on("/gate/close", [this]() { handleGateClose(); });
    _server.on("/gate/pulse", [this]() { handleGatePulse(); });
    _server.on("/gate/status", [this]() { handleGateStatus(); });
}

void WebServerHandler::handleRoot() {
    _server.send(200, "text/plain", "ESP32 garage online!");
}

void WebServerHandler::handleHealth() {
    _server.send(200, "text/plain", "OK");
}

void WebServerHandler::handleAuthInfo() {
    String json = "{";
    json += "\"auth_enabled\":" + String(_authConfig && _authConfig->isAuthEnabled() ? "true" : "false");
    
    if (_authConfig && _authConfig->isAuthEnabled()) {
        json += ",\"keycloak_server\":\"" + _authConfig->getKeycloakServerUrl() + "\"";
        json += ",\"realm\":\"" + _authConfig->getKeycloakRealm() + "\"";
        json += ",\"client_id\":\"" + _authConfig->getKeycloakClientId() + "\"";
        json += ",\"protected_routes\":[\"/gate/open\",\"/gate/close\",\"/gate/pulse\"]";
    }
    
    json += "}";
    
    _server.send(200, "application/json", json);
}

void WebServerHandler::handleGateOpen() {
    bool authenticated = requireAuthentication();
    
    // Log l'action (autorisée ou non)
    logGateAction("open", authenticated);
    
    if (!authenticated) {
        return;
    }
    
    GateState currentState = _gateController->readState();
    
    if (currentState != OPEN) {
        _gateController->triggerRelay();
        _gateMonitor->startOperation(OPENING, OPEN);
    }
    
    // Return current status in JSON format
    handleGateStatus();
}

void WebServerHandler::handleGateClose() {
    bool authenticated = requireAuthentication();
    
    // Log l'action (autorisée ou non)
    logGateAction("close", authenticated);
    
    if (!authenticated) {
        return;
    }
    
    GateState currentState = _gateController->readState();
    
    if (currentState != CLOSED) {
        _gateController->triggerRelay();
        _gateMonitor->startOperation(CLOSING, CLOSED);
    }
    
    // Return current status in JSON format
    handleGateStatus();
}

void WebServerHandler::handleGatePulse() {
    bool authenticated = requireAuthentication();

    logGateAction("pulse", authenticated);

    if (!authenticated) {
        return;
    }

    _gateController->triggerRelay();

    // A pulse actuator has no reliable direction: return sensors as observed.
    handleGateStatus();
}

void WebServerHandler::handleGateStatus() {
    String json = buildStatusJson();
    _server.send(200, "application/json", json);
}

String WebServerHandler::buildStatusJson() {
    bool sensorClosed = _gateController->isClosedSensorActive();
    bool sensorOpen = _gateController->isOpenSensorActive();
    GateState state = _gateController->readState();
    OperationState currentOperation = _gateMonitor->getCurrentOperation();
    
    String json = "{";
    json += "\"status\":\"";
    
    // Priority: ongoing operations override physical state
    if (currentOperation == OPENING) {
        json += "opening";
    } else if (currentOperation == CLOSING) {
        json += "closing";
    } else {
        // No operation, return physical state
        switch(state) {
            case CLOSED: json += "closed"; break;
            case OPEN: json += "open"; break;
            case UNKNOWN: json += "unknown"; break;
        }
    }
    
    json += "\",";
    json += "\"sensor_closed\":" + String(sensorClosed ? "true" : "false") + ",";
    json += "\"sensor_open\":" + String(sensorOpen ? "true" : "false") + ",";
    
    if (_gateMonitor->isOperationInProgress()) {
        json += "\"operation_time\":" + String(_gateMonitor->getOperationElapsedTime()) + ",";
        json += "\"timeout_remaining\":" + String(_gateMonitor->getOperationRemainingTime()) + ",";
    }
    
    json += "\"alert_active\":" + String(_gateMonitor->isAlertActive() ? "true" : "false") + ",";
    json += "\"auto_close_enabled\":" + String(_gateMonitor->isAutoCloseEnabled() ? "true" : "false");
    
    if (_gateMonitor->isAutoCloseEnabled() && state == OPEN && currentOperation == IDLE) {
        json += ",\"auto_close_remaining\":" + String(_gateMonitor->getAutoCloseRemainingTime());
    }
    
    json += "}";
    
    return json;
}

void WebServerHandler::initializeAuth() {
    _authConfig = &AuthConfig::getInstance();
    _authConfig->loadFromEnvironment();
    
    if (_authConfig->isAuthEnabled()) {
        _authMiddleware = new AuthMiddleware(_authConfig);
        Serial.println("Authentication middleware initialized");
    } else {
        Serial.println("Authentication is disabled");
    }
}

bool WebServerHandler::requireAuthentication() {
    if (!_authConfig || !_authConfig->isAuthEnabled()) {
        return true; // Pas d'auth requise
    }
    
    if (!_authMiddleware) {
        Serial.println("Auth middleware not initialized");
        _server.send(500, "application/json", "{\"error\":\"Internal server error\"}");
        return false;
    }
    
    if (!_authMiddleware->authenticateRequest(&_server)) {
        _authMiddleware->sendUnauthorizedResponse(&_server);
        return false;
    }
    
    return true;
}

void WebServerHandler::initializeEmqx() {
    _emqxConfig = new EmqxConfig();
    _emqxConfig->initialize();
    
    if (_emqxConfig->isEmqxEnabled() && _emqxConfig->isValid()) {
        _emqxLogger = new EmqxLogger(
            _emqxConfig->getBrokerHost(),
            _emqxConfig->getBrokerPort(),
            _emqxConfig->getUsername(),
            _emqxConfig->getPassword(),
            _emqxConfig->getClientId(),
            _emqxConfig->getTopic(),
            _emqxConfig->getUnauthorizedTopic()
        );
        
        if (_emqxLogger->begin()) {
            Serial.println("EMQX logger initialized and connected");
        } else {
            Serial.println("EMQX logger initialized but connection failed");
        }
    } else {
        Serial.println("EMQX logging is disabled");
    }
}

void WebServerHandler::logGateAction(const String& action, bool authorized) {
    if (!_emqxLogger || !_emqxConfig || !_emqxConfig->isEmqxEnabled()) {
        return; // EMQX non configuré
    }
    
    String sub = "";
    String name = "";
    String token = "";
    
    // Récupérer les informations du token si l'authentification est activée
    if (_authMiddleware && _authConfig && _authConfig->isAuthEnabled()) {
        ValidationResult result = _authMiddleware->getLastValidationResult();
        sub = result.userId;
        name = result.username;
        
        // Pour les actions non autorisées, récupérer le token complet
        if (!authorized) {
            String authHeader = _server.header("Authorization");
            if (authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }
        }
    }
    
    if (authorized) {
        _emqxLogger->logAuthorizedAction(action, sub, name);
    } else {
        _emqxLogger->logUnauthorizedAction(action, sub, name, token);
    }
}
