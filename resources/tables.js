import { tables } from 'harperdb';

// Helper to check if request has an authenticated OAuth session
function isAuthenticated(context) {
	return !!context.session?.oauth;
}

function isAdmin(context) {
	return context.session?.user?.role === 'admin';
}

// === SIEM Events ===
export class siem_events extends tables.siem_events {
	allowRead(user, target, context) {
		return isAuthenticated(context);
	}
	allowCreate(user, record, context) {
		return false; // System-only writes via poller
	}
	allowUpdate(user, record, context) {
		return false;
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Batch Analysis ===
export class siem_analysis_batch extends tables.siem_analysis_batch {
	allowRead(user, target, context) {
		return isAuthenticated(context);
	}
	allowCreate(user, record, context) {
		return false;
	}
	allowUpdate(user, record, context) {
		return false;
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Strategic Analysis ===
export class siem_analysis_strategic extends tables.siem_analysis_strategic {
	allowRead(user, target, context) {
		return isAuthenticated(context);
	}
	allowCreate(user, record, context) {
		return false;
	}
	allowUpdate(user, record, context) {
		return false;
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Polling State ===
export class siem_offsets extends tables.siem_offsets {
	allowRead(user, target, context) {
		return isAdmin(context);
	}
	allowCreate(user, record, context) {
		return false;
	}
	allowUpdate(user, record, context) {
		return false;
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Runtime Configuration ===
export class siem_config extends tables.siem_config {
	allowRead(user, target, context) {
		return isAdmin(context);
	}
	allowCreate(user, record, context) {
		return isAdmin(context);
	}
	allowUpdate(user, record, context) {
		return isAdmin(context);
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Cost Tracking ===
export class siem_cost_tracking extends tables.siem_cost_tracking {
	allowRead(user, target, context) {
		return isAdmin(context);
	}
	allowCreate(user, record, context) {
		return false;
	}
	allowUpdate(user, record, context) {
		return false;
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Event Exports ===
export class siem_exports extends tables.siem_exports {
	allowRead(user, target, context) {
		return isAuthenticated(context);
	}
	allowCreate(user, record, context) {
		return isAuthenticated(context);
	}
	allowUpdate(user, record, context) {
		return false;
	}
	allowDelete(user, target, context) {
		return false;
	}
}

// === Users ===
export class User extends tables.User {
	allowRead(user, target, context) {
		return isAuthenticated(context);
	}
	allowCreate(user, record, context) {
		return false; // Created via OAuth onLogin only
	}
	allowUpdate(user, record, context) {
		return false; // Updated via OAuth onLogin only
	}
	allowDelete(user, target, context) {
		return false;
	}
}
