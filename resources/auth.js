import { registerHooks } from '@harperfast/oauth';
import { tables, createBlob } from 'harperdb';

registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		const { User } = tables;

		// Find existing user by email
		let user;
		for await (const existing of User.search({ email: oauthUser.email })) {
			user = existing;
			break;
		}

		// Fetch profile picture as Blob if URL provided
		let pictureBlob = null;
		if (oauthUser.picture) {
			try {
				const res = await fetch(oauthUser.picture);
				if (res.ok) {
					const buffer = Buffer.from(await res.arrayBuffer());
					const contentType = res.headers.get('content-type') || 'image/jpeg';
					pictureBlob = createBlob(buffer, { type: contentType });
				}
			} catch (e) {
				// Picture fetch failed — UI will show first-initial placeholder
			}
		}

		if (!user) {
			// Create new user with default 'analyst' role
			user = await User.create({
				email: oauthUser.email,
				name: oauthUser.name,
				picture: pictureBlob,
				provider,
				role: 'analyst',
			});
		} else {
			// Update last login, name, and picture on every login
			await User.update(user.id, {
				lastLoginAt: new Date(),
				name: oauthUser.name,
				picture: pictureBlob,
			});
		}

		// Return data stored in session
		return { user: String(user.id), role: user.role };
	},
});
