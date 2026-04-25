/// Perform FormatMessage-compatible parameter substitution on `template`.
///
/// - `%1`-`%99`: replaced with `params[N-1]`; left as-is if out of range.
/// - `%%`: literal `%`
/// - `%n`: `\r\n`
/// - `%r`: `\r`
/// - `%t`: `\t`
/// - `%b`: space
/// - `%0`: truncate output here
pub fn substitute(template: &str, params: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let rest = &bytes[i + 1..];
        if rest.is_empty() {
            out.push('%');
            i += 1;
            continue;
        }
        match rest[0] {
            b'%' => {
                out.push('%');
                i += 2;
            }
            b'n' => {
                out.push('\r');
                out.push('\n');
                i += 2;
            }
            b'r' => {
                out.push('\r');
                i += 2;
            }
            b't' => {
                out.push('\t');
                i += 2;
            }
            b'b' => {
                out.push(' ');
                i += 2;
            }
            b'0' => {
                return out;
            }
            c if c.is_ascii_digit() && c != b'0' => {
                let d1 = (c - b'0') as usize;
                let (idx, advance) = if rest.len() > 1 && rest[1].is_ascii_digit() {
                    (d1 * 10 + (rest[1] - b'0') as usize, 3)
                } else {
                    (d1, 2)
                };
                if idx > 0 && idx <= params.len() {
                    out.push_str(params[idx - 1]);
                } else {
                    out.push_str(&template[i..i + advance]);
                }
                i += advance;
            }
            _ => {
                out.push('%');
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_single_param() {
        assert_eq!(
            substitute("Service %1 started.", &["Spooler"]),
            "Service Spooler started."
        );
    }
    #[test]
    fn two_params() {
        assert_eq!(
            substitute("Error %1: %2", &["5", "Access denied"]),
            "Error 5: Access denied"
        );
    }
    #[test]
    fn percent_literal() {
        assert_eq!(substitute("100%%", &[]), "100%");
    }
    #[test]
    fn newline_sequence() {
        assert_eq!(substitute("Line1%nLine2", &[]), "Line1\r\nLine2");
    }
    #[test]
    fn tab_sequence() {
        assert_eq!(substitute("Col1%tCol2", &[]), "Col1\tCol2");
    }
    #[test]
    fn space_sequence() {
        assert_eq!(substitute("%b", &[]), " ");
    }
    #[test]
    fn carriage_return_sequence() {
        assert_eq!(substitute("%r", &[]), "\r");
    }
    #[test]
    fn truncate_at_zero() {
        assert_eq!(substitute("msg%0trailing", &[]), "msg");
    }
    #[test]
    fn out_of_range_param_left_as_is() {
        assert_eq!(substitute("%3", &["a"]), "%3");
    }
    #[test]
    fn two_digit_param() {
        let mut params = vec!["x"; 12];
        params[11] = "twelve";
        assert_eq!(substitute("%12", &params), "twelve");
    }
    #[test]
    fn greedy_two_digit_out_of_range() {
        let params = vec!["a"; 9];
        assert_eq!(substitute("%12", &params), "%12");
    }
}
