//! Resolve OCI-style users against passwd and group records, at pull time or in the guest.
use std::io;

pub fn resolve_user(user: &str, passwd: &str, group: &str) -> io::Result<(u32, u32, String, Vec<u32>)> {
    let rows = |text: &str| -> Vec<Vec<String>> {
        text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split(':').map(String::from).collect::<Vec<_>>()).filter(|f| f.len() >= 3).collect()
    };
    let (passwd, group) = (rows(passwd), rows(group));
    // As in Docker, `user:` names no group.
    let (u, g) = user.split_once(':').map_or((user, None), |(u, g)| (u, Some(g).filter(|g| !g.is_empty())));
    let u = if u.is_empty() { "0" } else { u };
    let numeric_uid = u.parse::<u32>();
    let entry = passwd.iter().find(|f| match numeric_uid {
        Ok(uid) => f[2].parse::<u32>() == Ok(uid),
        Err(_) => f[0] == u,
    });
    let uid: u32 = match (numeric_uid, entry) {
        (Ok(n), _) => n,
        (Err(_), Some(f)) => f[2].parse().map_err(|_| io::Error::other(format!("bad uid for {u} in /etc/passwd")))?,
        (Err(_), None) => return Err(io::Error::other(format!("user {u:?} is not in the image's /etc/passwd"))),
    };
    let home = entry.and_then(|f| f.get(5)).filter(|h| !h.is_empty()).cloned().unwrap_or("/".into());
    let gid: u32 = match g {
        Some(g) => match g.parse() {
            Ok(n) => n,
            Err(_) => group
                .iter()
                .find(|f| f[0] == g)
                .and_then(|f| f[2].parse().ok())
                .ok_or_else(|| io::Error::other(format!("group {g:?} is not in the image's /etc/group")))?,
        },
        None => entry.and_then(|f| f.get(3)?.parse().ok()).unwrap_or(0),
    };
    let mut groups = vec![gid];
    if g.is_none() {
        let member = |f: &&Vec<String>| entry.is_some_and(|e| f.get(3).is_some_and(|m| m.split(',').any(|m| *m == e[0])));
        for n in group.iter().filter(member).filter_map(|f| f[2].parse().ok()) {
            if !groups.contains(&n) {
                groups.push(n);
            }
        }
    }
    Ok((uid, gid, home, groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_ids_match_values_and_names_match_only_names() {
        assert_eq!(resolve_user("01000", "app:x:1000:123::/home/app:", "").unwrap(), (1000, 123, "/home/app".into(), vec![123]));
        let passwd = "1000:x:42:43::/numeric-name:\napp:x:01000:123::/home/app:\n";
        let group = "2000:x:44:\nextra:x:02000:app\n";
        for user in ["1000", "01000", "app"] {
            assert_eq!(resolve_user(user, passwd, group).unwrap(), (1000, 123, "/home/app".into(), vec![123, 2000]));
            for g in ["2000", "02000", "extra"] {
                assert_eq!(resolve_user(&format!("{user}:{g}"), passwd, group).unwrap(), (1000, 2000, "/home/app".into(), vec![2000]));
            }
        }
        assert_eq!(resolve_user("9999:09999", passwd, group).unwrap(), (9999, 9999, "/".into(), vec![9999]));
        assert!(resolve_user("missing", passwd, group).is_err());
        assert!(resolve_user("app:missing", passwd, group).is_err());
    }
}
