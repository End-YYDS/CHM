use crate::handles::chm::role::types::Color;
use chm_grpc::restful::Color as GrpcColor;

impl From<GrpcColor> for Color {
    fn from(c: GrpcColor) -> Self {
        match c.kind {
            Some(chm_grpc::restful::color::Kind::Predefined(n)) => match n {
                0 => Color::Blue,
                1 => Color::Red,
                2 => Color::Green,
                3 => Color::Yellow,
                4 => Color::Purple,
                5 => Color::Orange,
                6 => Color::Black,
                7 => Color::White,
                8 => Color::Gray,
                _ => Color::Gray, // default fallback
            },
            Some(chm_grpc::restful::color::Kind::Custom(s)) => Color::Custom(s),
            None => Color::Gray, // default
        }
    }
}
impl Default for Color {
    fn default() -> Self {
        Color::Gray
    }
}
impl From<Color> for GrpcColor {
    fn from(c: Color) -> Self {
        match c {
            Color::Red => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(1)) },
            Color::Green => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(2)) },
            Color::Blue => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(0)) },
            Color::Yellow => {
                GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(3)) }
            }
            Color::Purple => {
                GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(4)) }
            }
            Color::Orange => {
                GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(5)) }
            }
            Color::Black => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(6)) },
            Color::White => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(7)) },
            Color::Gray => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Predefined(8)) },
            Color::Custom(s) => GrpcColor { kind: Some(chm_grpc::restful::color::Kind::Custom(s)) },
        }
    }
}
