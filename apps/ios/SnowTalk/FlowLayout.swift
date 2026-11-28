import SwiftUI

/// Wraps chips onto as many lines as needed, each as wide as its label.
/// (iOS 15 has no `Layout` protocol, so this uses alignment guides.)
struct Flow<Item: Hashable, Content: View>: View {
    let items: [Item]
    var spacing: CGFloat = 6
    @ViewBuilder let content: (Item) -> Content
    @State private var height: CGFloat = 0

    var body: some View {
        GeometryReader { geo in
            var x: CGFloat = 0
            var y: CGFloat = 0
            ZStack(alignment: .topLeading) {
                ForEach(items, id: \.self) { item in
                    content(item)
                        .alignmentGuide(.leading) { d in
                            if x + d.width > geo.size.width {
                                x = 0
                                y += d.height + spacing
                            }
                            let result = -x
                            x += d.width + spacing
                            return result
                        }
                        .alignmentGuide(.top) { _ in
                            let result = -y
                            if item == items.last { x = 0; y = 0 }
                            return result
                        }
                }
            }
            .background(GeometryReader { g in
                Color.clear.preference(key: FlowHeight.self, value: g.size.height)
            })
        }
        .frame(height: height)
        .onPreferenceChange(FlowHeight.self) { height = $0 }
    }
}

private struct FlowHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}
