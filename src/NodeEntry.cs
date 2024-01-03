namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    internal class NodeEntry
    {
        internal readonly byte[] nodeValue;
        internal readonly uint nodeHeight;

        internal NodeEntry(byte[] nodeValue, uint nodeHeight)
        {
            this.nodeValue = nodeValue;
            this.nodeHeight = nodeHeight;
        }
    }
}
